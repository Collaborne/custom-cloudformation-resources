import {
	CreateRuleGroupCommand,
	DeleteRuleGroupCommand,
	GetRuleGroupCommand,
	ListRuleGroupsCommand,
	UpdateRuleGroupCommand,
	WAFV2Client,
	type GetRuleGroupCommandOutput,
	type Rule,
} from '@aws-sdk/client-wafv2';
import { SchemaType } from '@collaborne/json-schema-to-type';

import { CustomResource, Response } from '../custom-resource';
import { Logger } from '../logger';

const SCHEMA = {
	type: 'object' as const,
	properties: {
		Name: {
			type: 'string' as const,
		},
		Description: {
			type: 'string' as const,
		},
		Capacity: {
			type: 'number' as const,
		},
		Rules: {
			type: 'string' as const,
		},
	},
	required: ['Name', 'Capacity'],
};

const SCOPE = 'CLOUDFRONT' as const;

interface ResourceAttributes {
	Arn: string;
	Id: string;
}

export class CloudFrontWafV2RuleGroup extends CustomResource<
	ResourceAttributes,
	typeof SCHEMA
> {
	region = 'us-east-1'; // Region must be `us-east-1` for `CloudFront WAF`

	private wafV2 = new WAFV2Client({
		region: this.region,
	});

	constructor(logicalResourceId: string, logger: Logger) {
		super(SCHEMA, logicalResourceId, logger);
	}

	public async createResource(
		physicalResourceId: string,
		{ Name, Description, Capacity, Rules }: SchemaType<typeof SCHEMA>,
	): Promise<Response<ResourceAttributes>> {
		const rules: Rule[] = JSON.parse(Rules);
		const ruleGroupParams = {
			Name,
			Description,
			Scope: SCOPE,
			Capacity,
			Rules: rules,
			VisibilityConfig: {
				SampledRequestsEnabled: true,
				CloudWatchMetricsEnabled: true,
				MetricName: 'CommonAttackRuleGroup',
			},
		};

		const { Summary: summary } = await this.wafV2.send(
			new CreateRuleGroupCommand(ruleGroupParams),
		);

		if (!summary?.ARN || !summary.Id) {
			throw new Error('AWS did not return the created rule-group identifiers');
		}
		this.logger.debug('Rule group created successfully', { arn: summary.ARN });

		return {
			physicalResourceId,
			attributes: {
				Arn: summary.ARN,
				Id: summary.Id,
			},
		};
	}

	public async deleteResource(
		physicalResourceId: string,
		{ Name }: SchemaType<typeof SCHEMA>,
	): Promise<Response<ResourceAttributes>> {
		const ruleGroup = await this.getRuleGroup(Name);

		if (
			!ruleGroup.RuleGroup?.ARN ||
			!ruleGroup.RuleGroup.Id ||
			!ruleGroup.LockToken
		) {
			throw new Error(`Rule group is not deletable ${Name}`);
		}

		await this.wafV2.send(
			new DeleteRuleGroupCommand({
				Name,
				Scope: SCOPE,
				Id: ruleGroup.RuleGroup?.Id,
				LockToken: ruleGroup.LockToken,
			}),
		);

		return {
			physicalResourceId,
		};
	}

	public async updateResource(
		physicalResourceId: string,
		{ Name, Description, Rules }: SchemaType<typeof SCHEMA>,
	): Promise<Response<ResourceAttributes>> {
		const ruleGroup = await this.getRuleGroup(Name);

		if (
			!ruleGroup.RuleGroup?.ARN ||
			!ruleGroup.RuleGroup.Id ||
			!ruleGroup.LockToken
		) {
			throw new Error(`Rule group is not updatable ${Name}`);
		}

		const rules: Rule[] = JSON.parse(Rules);

		const updateRuleGroupParams = {
			Id: ruleGroup.RuleGroup.Id,
			Name,
			Description,
			Scope: SCOPE,
			Rules: rules,
			VisibilityConfig: ruleGroup.RuleGroup.VisibilityConfig,
			LockToken: ruleGroup.LockToken,
		};

		await this.wafV2.send(new UpdateRuleGroupCommand(updateRuleGroupParams));

		return {
			physicalResourceId,
			attributes: {
				Arn: ruleGroup.RuleGroup.ARN,
				Id: ruleGroup.RuleGroup.Id,
			},
		};
	}

	protected async getRuleGroup(
		name: string,
	): Promise<GetRuleGroupCommandOutput> {
		let nextMarker: string | undefined;
		do {
			const page = await this.wafV2.send(
				new ListRuleGroupsCommand({ Scope: SCOPE, NextMarker: nextMarker }),
			);
			const summary = page.RuleGroups?.find(group => group.Name === name);
			if (summary?.Id && summary.ARN) {
				return this.wafV2.send(
					new GetRuleGroupCommand({
						Name: name,
						Id: summary.Id,
						ARN: summary.ARN,
						Scope: SCOPE,
					}),
				);
			}
			nextMarker = page.NextMarker;
		} while (nextMarker);

		throw new Error(`Unknown rule group name ${name}`);
	}
}
