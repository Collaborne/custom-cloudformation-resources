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
			type: 'object' as const,
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
		const rules = Rules as Rules;
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
		{ Name: name }: SchemaType<typeof SCHEMA>,
	): Promise<Response<ResourceAttributes>> {
		const attributes = await this.getRuleGroupAttributes(name);
		await this.wafV2
			.deleteRuleGroup({
				Name: name,
				Scope: SCOPE,
				Id: attributes.Id,
				LockToken: `${name}-delete-token`,
			})
			.promise();

		return {
			physicalResourceId,
		};
	}

	public async updateResource(
		physicalResourceId: string,
		{ Name: name }: SchemaType<typeof SCHEMA>,
	): Promise<Response<ResourceAttributes>> {
		const attributes = await this.getRuleGroupAttributes(name);

		return {
			physicalResourceId,
			attributes,
		};
	}

	protected async getRuleGroupAttributes(
		name: string,
	): Promise<ResourceAttributes> {
		const ruleGroup = await this.wafV2.getRuleGroup({ Name: name }).promise();
		if (!ruleGroup) {
			throw new Error(`Unknown rule group name ${name}`);
		}

		if (!ruleGroup.RuleGroup?.ARN || !ruleGroup.RuleGroup.Id) {
			throw new Error(`Missing properties for rule group ${name}`);
		}

		return {
			Arn: ruleGroup.RuleGroup?.ARN,
			Id: ruleGroup.RuleGroup?.Id,
		};
	}
}
