import { CloudWatchEvents } from 'aws-sdk';
import { crc32 } from 'crc';

import type { ObjectSchema, SchemaType } from '@collaborne/json-schema-to-type';

import {
	CustomResourceRequest,
	ResponseStatus,
	send as sendResponse,
} from './cfn-response';
import { Logger } from './logger';

export interface Response<ResourceAttributes extends unknown> {
	physicalResourceId?: string;
	attributes?: ResourceAttributes;
}

/**
 * Response returned by the resource methods to indicate that long-running continuation is needed
 */
export interface ContinuationRequired<ContinuationAttributes extends unknown> {
	/** Number of seconds after which to retry the function */
	continuationAfter: number;

	/** Additional properties that should be provided in the continuation invocation */
	continuationAttributes: ContinuationAttributes;
}

function isContinuationRequired<RA, CA>(
	response?: Response<RA> | ContinuationRequired<CA>,
): response is ContinuationRequired<CA> {
	return typeof response === 'object' && 'continuationAfter' in response;
}

type ContinuedCustomResourceRequest<ContinuationAttributes> =
	CustomResourceRequest & {
		ContinuationAttributes: ContinuationAttributes;
	};
function isContinuedCustomResourceRequest<ContinuationAttributes>(
	request:
		| CustomResourceRequest
		| ContinuedCustomResourceRequest<ContinuationAttributes>,
): request is ContinuedCustomResourceRequest<ContinuationAttributes> {
	return (
		'ContinuationAttributes' in request &&
		typeof request.ContinuationAttributes === 'object'
	);
}

export abstract class CustomResource<
	ResourceAttributes extends unknown,
	S extends ObjectSchema,
	ContinuationAttributes extends unknown = unknown,
> {
	private static CW_EVENTS_TARGET_ID = 'CustomResource';

	private cwEvents = new CloudWatchEvents({ apiVersion: '2015-10-07' });
	private requestQueue: (() => Promise<void>)[] = [];

	constructor(
		protected readonly schema: S,
		protected readonly logicalResourceId: string,
		protected readonly logger: Logger,
	) {}

	public abstract createResource(
		physicalResourceId: string,
		params: SchemaType<S>,
		continuationAttributes?: ContinuationAttributes,
	): Promise<
		Response<ResourceAttributes> | ContinuationRequired<ContinuationAttributes>
	>;

	public abstract deleteResource(
		physicalResourceId: string,
		params: SchemaType<S>,
		continuationAttributes?: ContinuationAttributes,
	): Promise<
		Response<ResourceAttributes> | ContinuationRequired<ContinuationAttributes>
	>;

	public abstract updateResource(
		physicalResourceId: string,
		params: SchemaType<S>,
		oldParams: unknown,
		continuationAttributes?: ContinuationAttributes,
	): Promise<
		Response<ResourceAttributes> | ContinuationRequired<ContinuationAttributes>
	>;

	public handleRequest(
		request:
			| CustomResourceRequest
			| ContinuedCustomResourceRequest<ContinuationAttributes>,
	): Promise<ResponseStatus> {
		let resolveRequest: (response: ResponseStatus) => void;
		let rejectRequest: (error: Error) => void;
		const result = new Promise<ResponseStatus>((resolve, reject) => {
			resolveRequest = resolve;
			rejectRequest = reject;
		});

		const processThisRequest = async () => {
			try {
				const { status } = await this.processRequest(request);
				resolveRequest(status);
			} catch (err) {
				rejectRequest(err);
			} finally {
				// Remove ourselves from the queue, and execute the next one.
				this.requestQueue.shift();
				const processNextRequest =
					this.requestQueue.length > 0 ? this.requestQueue[0] : undefined;
				if (processNextRequest) {
					void processNextRequest();
				}
			}
		};

		if (this.requestQueue.push(processThisRequest) === 1) {
			// What we added is the first entry, so start executing it.
			void processThisRequest();
		}
		return result;
	}

	protected async processRequest(
		request:
			| CustomResourceRequest
			| ContinuedCustomResourceRequest<ContinuationAttributes>,
	): Promise<{
		status: ResponseStatus;
	}> {
		// TODO: validate the parameters to conform to the schema

		// Default physical resource id
		const physicalResourceId =
			request.PhysicalResourceId ||
			[request.StackId, request.LogicalResourceId, request.RequestId].join('/');

		let continuationAttributes: ContinuationAttributes | undefined;
		if (isContinuedCustomResourceRequest(request)) {
			this.logger.log('Request is a continuation of an earlier request');
			continuationAttributes = request.ContinuationAttributes;
		}
		let status: ResponseStatus = 'FAILED';
		let statusReason: string | undefined;
		let response:
			| Response<ResourceAttributes>
			| ContinuationRequired<ContinuationAttributes>
			| undefined;
		try {
			const { ServiceToken: _ignoredServiceToken, ...properties } =
				request.ResourceProperties;
			switch (request.RequestType) {
				case 'Create':
					response = await this.createResource(
						physicalResourceId,
						properties as SchemaType<S>,
						continuationAttributes as ContinuationAttributes,
					);
					break;
				case 'Delete':
					response = await this.deleteResource(
						physicalResourceId,
						properties as SchemaType<S>,
						continuationAttributes as ContinuationAttributes,
					);
					break;
				case 'Update':
					{
						// Note that the old properties could be a completely different schema. It's the job of the developer
						// of the template to prevent/handle that.
						const { ServiceToken: _ignoredOldServiceToken, ...oldProperties } =
							request.OldResourceProperties!;
						response = await this.updateResource(
							physicalResourceId,
							properties as SchemaType<S>,
							oldProperties,
							continuationAttributes as ContinuationAttributes,
						);
					}
					break;
			}

			status = 'SUCCESS';
		} catch (err) {
			this.logger.warn(
				`Uncaught error when handling request "${request.RequestType}": ${err.message}`,
			);
			statusReason = err.message;
		}

		if (isContinuationRequired(response)) {
			// Schedule the invocation of the function again, with the additional attributes from
			// the response
			const { continuationAfter, continuationAttributes } = response;
			const continuationRuleName = this.getContinuationRuleName(request);

			// XXX: Magic! Needs to be documented that this can be set to an ARN of the role to use.
			const ruleRoleArn = process.env.CW_EVENTS_CONTINUATION_RULE_ROLE_ARN;

			// Ideally we want to put the target for the continuation first so that we don't miss
			// our own goal, but CWE doesn't work this way.
			// What does work however is to create the rule with a schedule expression pointing to a
			// day in the past, keep it "DISABLED", then add the target, and then update the rule to
			// enable it with a suitably-in-the-future expression.
			// Note that if the rule already exists this will similarly first disable it; as the rule name
			// and target ID are constant over the life-time of the rule this should all be idempotent.
			const prepPutRuleParams: CloudWatchEvents.PutRuleRequest = {
				Name: continuationRuleName,
				RoleArn: ruleRoleArn,
				ScheduleExpression: `cron(30 7 19 6 ? 2018)`,
				State: 'DISABLED',
			};
			await this.cwEvents.putRule(prepPutRuleParams).promise();

			const putTargetsParams: CloudWatchEvents.PutTargetsRequest = {
				Rule: continuationRuleName,
				Targets: [
					{
						Arn: request.ServiceToken,
						Id: CustomResource.CW_EVENTS_TARGET_ID,
						Input: JSON.stringify({
							...request,
							ContinuationAttributes: continuationAttributes,
						}),
						RoleArn: process.env.CW_EVENTS_CONTINUATION_TARGET_ROLE_ARN,
					},
				],
			};
			await this.cwEvents.putTargets(putTargetsParams).promise();

			const now = new Date();
			const when = new Date(now.getTime() + continuationAfter * 1000);
			// Round up to the next full minute, as we won't be getting scheduling if the time isn't in the future.
			const cronExpression = `${Math.max(
				now.getMinutes() + 1,
				when.getMinutes(),
			)} ${when.getHours()} ${when.getDate()} ${
				when.getMonth() + 1
			} ? ${when.getFullYear()}`;

			this.logger.log(
				`Scheduling continuation using CWE rule ${continuationRuleName} after ${continuationAfter}s (at ${cronExpression}) `,
			);
			const schedulePutRuleParams: CloudWatchEvents.PutRuleRequest = {
				Name: continuationRuleName,
				RoleArn: ruleRoleArn,
				ScheduleExpression: `cron(${cronExpression})`,
				State: 'ENABLED',
			};
			await this.cwEvents.putRule(schedulePutRuleParams).promise();
		} else {
			// A "definite" status, so write that into the response document
			const responsePhysicalResourceId =
				response?.physicalResourceId || physicalResourceId;
			await sendResponse(
				request,
				status,
				statusReason,
				responsePhysicalResourceId,
				response?.attributes,
			);

			// If there are continuation attributes in the request, we know that this was a continuation
			// and therefore we now want to remove the rule.
			if (continuationAttributes) {
				const continuationRuleName = this.getContinuationRuleName(request);
				this.logger.log(`Cleaning up CWE rule ${continuationRuleName}`);
				try {
					await this.cwEvents
						.removeTargets({
							Rule: continuationRuleName,
							Ids: [CustomResource.CW_EVENTS_TARGET_ID],
						})
						.promise();
					await this.cwEvents
						.deleteRule({
							Name: continuationRuleName,
						})
						.promise();
				} catch (err) {
					// Best effort, didn't work, bad luck.
					// Given that the rule is a single date, this should merely produce garbage in CW Events, but not produce
					// any other side-effects.
					this.logger.warn(
						`Cannot remove continuation rule ${continuationRuleName}: ${err.message}`,
					);
				}
			}
		}
		return {
			status,
		};
	}

	private getContinuationRuleName(request: CustomResourceRequest): string {
		// Rule name, can be at most 64 characters and has a limited range of valid characters
		// We also know the rule must be unique for this request, so we try to cram as much as we can
		// into it.

		// StackId is something like "arn:aws:cloudformation:us-west-2:123456789012:stack/stack-name/guid", for our purposes
		// we care only about the stack name.
		const [, stackName] = request.StackId.split(/:/)[5].split(/\//);
		const safeRequestId = crc32(request.RequestId).toString(16);

		const continuationRuleName = `Continuation-${stackName}-${request.LogicalResourceId}`;
		return `${continuationRuleName.slice(0, 55)}-${safeRequestId}`;
	}
}
