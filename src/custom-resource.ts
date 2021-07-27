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

export abstract class CustomResource<
	ResourceAttributes extends unknown,
	S extends ObjectSchema,
> {
	private requestQueue: (() => Promise<void>)[] = [];

	constructor(
		protected readonly schema: S,
		protected readonly logicalResourceId: string,
		protected readonly logger: Logger,
	) {}

	public abstract createResource(
		physicalResourceId: string,
		params: SchemaType<S>,
	): Promise<Response<ResourceAttributes>>;

	public abstract deleteResource(
		physicalResourceId: string,
		params: SchemaType<S>,
	): Promise<Response<ResourceAttributes>>;

	public abstract updateResource(
		physicalResourceId: string,
		params: SchemaType<S>,
		oldParams: unknown,
	): Promise<Response<ResourceAttributes>>;

	public handleRequest(
		request: CustomResourceRequest,
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

	protected async processRequest(request: CustomResourceRequest): Promise<{
		status: ResponseStatus;
		statusReason?: string;
		response: Response<ResourceAttributes>;
	}> {
		// TODO: validate the parameters to conform to the schema

		// Default physical resource id
		const physicalResourceId =
			request.PhysicalResourceId ||
			[request.StackId, request.LogicalResourceId, request.RequestId].join('/');

		let status: ResponseStatus = 'FAILED';
		let statusReason: string | undefined;
		let response: Response<ResourceAttributes> | undefined;
		try {
			const { ServiceToken: _ignoredServiceToken, ...properties } =
				request.ResourceProperties;
			switch (request.RequestType) {
				case 'Create':
					response = await this.createResource(
						physicalResourceId,
						properties as SchemaType<S>,
					);
					break;
				case 'Delete':
					response = await this.deleteResource(
						physicalResourceId,
						properties as SchemaType<S>,
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

		const responsePhysicalResourceId =
			response?.physicalResourceId || physicalResourceId;
		await sendResponse(
			request,
			status,
			statusReason,
			responsePhysicalResourceId,
			response?.attributes,
		);
		return {
			status,
			statusReason,
			response: {
				physicalResourceId: responsePhysicalResourceId,
				attributes: response?.attributes,
			},
		};
	}
}
