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
		MetricName: {
			type: 'string' as const,
		},
		Rules: {
			type: 'string' as const,
		},
	},
	required: ['Name', 'MetricName'],
};

const SCOPE = 'CLOUDFRONT';

interface ResourceAttributes {
	Arn: string;
	Id: string;
}

export class CloudFrontWafV2 extends CustomResource<
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
		{ Name, MetricName, Rules }: SchemaType<typeof SCHEMA>,
	): Promise<Response<ResourceAttributes>> {
		const rules: Rules = JSON.parse(Rules);
		const webACLParams = {
			Name,
			Scope: SCOPE,
			DefaultAction: {
				Allow: {},
			},
			Rules: rules,
			VisibilityConfig: {
				MetricName,
				SampledRequestsEnabled: true,
				CloudWatchMetricsEnabled: true,
			},
		};

		try {
			const webAcl = await this.wafV2.createWebACL(webACLParams).promise();

			if (!webAcl || !webAcl.Summary?.ARN || !webAcl.Summary.Id) {
				throw new Error('Error creating WebACL');
			}
			console.debug('WebACL created successfully:', webAcl.Summary?.ARN);

			return {
				physicalResourceId,
				attributes: {
					Arn: webAcl.Summary?.ARN,
					Id: webAcl.Summary?.Id,
				},
			};
		} catch (err) {
			console.error('Error creating WebACL:', err);
			throw new Error('Error creating WebACL');
		}
	}

	public async deleteResource(
		physicalResourceId: string,
		{ Name }: SchemaType<typeof SCHEMA>,
	): Promise<Response<ResourceAttributes>> {
		const webAcl = await this.getWebAcl(Name);

		if (!webAcl.WebACL || !webAcl.LockToken) {
			throw new Error(`WAF V2 is not deletable ${Name}`);
		}

		this.wafV2.deleteWebACL({
			Name,
			Scope: SCOPE,
			Id: webAcl.WebACL.Id,
			LockToken: webAcl.LockToken,
		});

		return {
			physicalResourceId,
		};
	}

	public async updateResource(
		physicalResourceId: string,
		{ Name, Rules }: SchemaType<typeof SCHEMA>,
	): Promise<Response<ResourceAttributes>> {
		const webAcl = await this.getWebAcl(Name);

		if (!webAcl.WebACL || !webAcl.LockToken) {
			throw new Error(`WAF V2 is not able to update ${Name}`);
		}

		const rules: Rules = JSON.parse(Rules);

		const updateWebAclParams = {
			Id: webAcl.WebACL.Id,
			Name,
			DefaultAction: webAcl.WebACL.DefaultAction,
			Scope: SCOPE,
			Rules: rules,
			VisibilityConfig: webAcl.WebACL.VisibilityConfig,
			LockToken: webAcl.LockToken,
		};

		await this.wafV2.updateWebACL(updateWebAclParams).promise();

		console.warn(`WAF V2 is updated ${Name}`);

		return {
			physicalResourceId,
			attributes: {
				Arn: webAcl.WebACL?.ARN,
				Id: webAcl.WebACL?.Id,
			},
		};
	}

	protected async getWebAcl(name: string): Promise<WAFV2.GetWebACLResponse> {
		const webAcls = await this.wafV2.listWebACLs({ Scope: SCOPE }).promise();
		if (!webAcls) {
			throw new Error(`Unknown waf name ${name}`);
		}

		const webAclSummary = webAcls.WebACLs?.find(webAcl => webAcl.Name === name);
		if (!webAclSummary || !webAclSummary.ARN || !webAclSummary.Id) {
			throw new Error(`Unknown waf name ${name}`);
		}

		const webAcl = await this.wafV2
			.getWebACL({
				Name: name,
				Id: webAclSummary.Id,
				Scope: SCOPE,
			})
			.promise();

		return webAcl;
	}
}
