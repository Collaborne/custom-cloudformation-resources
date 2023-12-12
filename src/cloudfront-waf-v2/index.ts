import { WAFV2 } from 'aws-sdk';

import { SchemaType } from '@collaborne/json-schema-to-type';

import { CustomResource, Response } from '../custom-resource';
import { Logger } from '../logger';

const SCHEMA = {
	type: 'object' as const,
	properties: {
		Name: {
			type: 'string' as const,
		},
		MetricName: {
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
		{ Name, MetricName }: SchemaType<typeof SCHEMA>,
	): Promise<Response<ResourceAttributes>> {
		const webACLParams = {
			Name,
			Scope: SCOPE,
			DefaultAction: {
				Allow: {},
			},
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
			console.log('WebACL created successfully:', webAcl.Summary?.ARN);

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
		{ Name: name }: SchemaType<typeof SCHEMA>,
	): Promise<Response<ResourceAttributes>> {
		const attributes = await this.getWebAclAttributes(name);
		this.wafV2.deleteWebACL({
			Name: name,
			Scope: SCOPE,
			Id: attributes.Id,
			LockToken: 'RemoveWAF',
		});

		return {
			physicalResourceId,
		};
	}

	public async updateResource(
		physicalResourceId: string,
		{ Name: name }: SchemaType<typeof SCHEMA>,
	): Promise<Response<ResourceAttributes>> {
		const attributes = await this.getWebAclAttributes(name);

		return {
			physicalResourceId,
			attributes,
		};
	}

	protected async getWebAclAttributes(
		name: string,
	): Promise<ResourceAttributes> {
		const webAcls = await this.wafV2.listWebACLs({ Scope: SCOPE }).promise();
		if (!webAcls) {
			throw new Error(`Unknown waf name ${name}`);
		}

		const webAcl = webAcls.WebACLs?.find(webAcl => webAcl.Name === name);
		if (!webAcl || !webAcl.ARN || !webAcl.Id) {
			throw new Error(`Unknown waf name ${name}`);
		}

		return {
			Arn: webAcl?.ARN,
			Id: webAcl?.Id,
		};
	}
}
