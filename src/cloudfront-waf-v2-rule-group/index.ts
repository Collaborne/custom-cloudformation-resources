import { WAFV2 } from 'aws-sdk';

import { SchemaType } from '@collaborne/json-schema-to-type';

import { CustomResource, Response } from '../custom-resource';
import { Logger } from '../logger';
import { Rules } from 'aws-sdk/clients/wafv2';

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

const SCOPE = 'CLOUDFRONT';

interface ResourceAttributes {
	Arn: string;
	Id: string;
}

export class CloudFrontWafV2RuleGroup extends CustomResource<
	ResourceAttributes,
	typeof SCHEMA
> {
	region = 'us-east-1'; // Region must be `us-east-1` for `CloudFront WAF`

	private wafV2 = new WAFV2({
		region: this.region,
	});

	constructor(logicalResourceId: string, logger: Logger) {
		super(SCHEMA, logicalResourceId, logger);
	}

	public async createResource(
		physicalResourceId: string,
		{ Name, Description, Capacity, Rules }: SchemaType<typeof SCHEMA>,
	): Promise<Response<ResourceAttributes>> {
		const rules: Rules = JSON.parse(Rules);
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

		console.log(`ruleGroupParams: ${JSON.stringify(ruleGroupParams)}`);

		try {
			const ruleGroup = await this.wafV2
				.createRuleGroup(ruleGroupParams)
				.promise();

			if (!ruleGroup || !ruleGroup.Summary?.ARN || !ruleGroup.Summary.Id) {
				throw new Error('Error creating Rule Group');
			}
			console.log('Rule Group created successfully:', ruleGroup.Summary?.ARN);

			return {
				physicalResourceId,
				attributes: {
					Arn: ruleGroup.Summary?.ARN,
					Id: ruleGroup.Summary?.Id,
				},
			};
		} catch (err) {
			console.error('Error creating Rule Group:', err);
			throw new Error('Error creating Rule Group');
		}
	}

	public async deleteResource(
		physicalResourceId: string,
		{ Name }: SchemaType<typeof SCHEMA>,
	): Promise<Response<ResourceAttributes>> {
		const ruleGroup = await this.getRuleGroup(Name);

		if (!ruleGroup.RuleGroup || !ruleGroup.LockToken) {
			throw new Error(`Rule group is not deletable ${Name}`);
		}

		await this.wafV2
			.deleteRuleGroup({
				Name,
				Scope: SCOPE,
				Id: ruleGroup.RuleGroup?.Id,
				LockToken: ruleGroup.LockToken,
			})
			.promise();

		return {
			physicalResourceId,
		};
	}

	public async updateResource(
		physicalResourceId: string,
		{ Name, Description, Rules }: SchemaType<typeof SCHEMA>,
	): Promise<Response<ResourceAttributes>> {
		const ruleGroup = await this.getRuleGroup(Name);

		if (!ruleGroup.RuleGroup || !ruleGroup.LockToken) {
			throw new Error(`Rule group is not updatable ${Name}`);
		}

		const rules: Rules = JSON.parse(Rules);

		const updateRuleGroupParams = {
			Id: ruleGroup.RuleGroup.Id,
			Name,
			Description,
			Scope: SCOPE,
			Rules: rules,
			VisibilityConfig: ruleGroup.RuleGroup.VisibilityConfig,
			LockToken: ruleGroup.LockToken,
		};
		console.log(
			`updateRuleGroupParams: ${JSON.stringify(updateRuleGroupParams)}`,
		);

		await this.wafV2.updateRuleGroup(updateRuleGroupParams).promise();

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
	): Promise<WAFV2.GetRuleGroupResponse> {
		const ruleGroups = await this.wafV2
			.listRuleGroups({ Scope: SCOPE })
			.promise();

		if (!ruleGroups.RuleGroups || ruleGroups.RuleGroups.length < 1) {
			throw new Error(
				`There is no rule groups in your account with scope ${SCOPE}`,
			);
		}

		const ruleGroupSummary = ruleGroups.RuleGroups.find(x => x.Name === name);

		if (!ruleGroupSummary) {
			throw new Error(`Unknown rule group name ${name}`);
		}

		const ruleGroup = await this.wafV2
			.getRuleGroup({
				Name: name,
				Id: ruleGroupSummary.Id,
				ARN: ruleGroupSummary.ARN,
				Scope: SCOPE,
			})
			.promise();

		if (!ruleGroup.RuleGroup) {
			throw new Error(`Rule group cannot find for ${name}`);
		}

		return ruleGroup;
	}
}
