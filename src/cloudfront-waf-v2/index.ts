import {
	CreateWebACLCommand,
	DeleteWebACLCommand,
	GetWebACLCommand,
	ListWebACLsCommand,
	UpdateWebACLCommand,
	WAFV2Client,
	type GetWebACLCommandOutput,
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
		MetricName: {
			type: 'string' as const,
		},
		Rules: {
			type: 'string' as const,
		},
	},
	required: ['Name', 'MetricName'],
};

const SCOPE = 'CLOUDFRONT' as const;

interface ResourceAttributes {
	Arn: string;
	Id: string;
}

export class CloudFrontWafV2 extends CustomResource<
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
		{ Name, MetricName, Rules }: SchemaType<typeof SCHEMA>,
	): Promise<Response<ResourceAttributes>> {
		const rules: Rule[] = JSON.parse(Rules);
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

		const { Summary: summary } = await this.wafV2.send(
			new CreateWebACLCommand(webACLParams),
		);

		if (!summary?.ARN || !summary.Id) {
			throw new Error('AWS did not return the created WebACL identifiers');
		}
		this.logger.debug('WebACL created successfully', { arn: summary.ARN });

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
		const webAcl = await this.getWebAcl(Name);

		if (!webAcl.WebACL?.ARN || !webAcl.WebACL.Id || !webAcl.LockToken) {
			throw new Error(`WAF V2 is not deletable ${Name}`);
		}

		await this.wafV2.send(
			new DeleteWebACLCommand({
				Name,
				Scope: SCOPE,
				Id: webAcl.WebACL.Id,
				LockToken: webAcl.LockToken,
			}),
		);

		return {
			physicalResourceId,
		};
	}

	public async updateResource(
		physicalResourceId: string,
		{ Name, Rules }: SchemaType<typeof SCHEMA>,
	): Promise<Response<ResourceAttributes>> {
		const webAcl = await this.getWebAcl(Name);

		if (!webAcl.WebACL?.ARN || !webAcl.WebACL.Id || !webAcl.LockToken) {
			throw new Error(`WAF V2 is not able to update ${Name}`);
		}

		const rules: Rule[] = JSON.parse(Rules);

		const updateWebAclParams = {
			Id: webAcl.WebACL.Id,
			Name,
			DefaultAction: webAcl.WebACL.DefaultAction,
			Scope: SCOPE,
			Rules: rules,
			VisibilityConfig: webAcl.WebACL.VisibilityConfig,
			LockToken: webAcl.LockToken,
		};

		await this.wafV2.send(new UpdateWebACLCommand(updateWebAclParams));

		this.logger.log(`WAF V2 is updated ${Name}`);

		return {
			physicalResourceId,
			attributes: {
				Arn: webAcl.WebACL.ARN,
				Id: webAcl.WebACL.Id,
			},
		};
	}

	protected async getWebAcl(name: string): Promise<GetWebACLCommandOutput> {
		let nextMarker: string | undefined;
		do {
			const page = await this.wafV2.send(
				new ListWebACLsCommand({ Scope: SCOPE, NextMarker: nextMarker }),
			);
			const summary = page.WebACLs?.find(webAcl => webAcl.Name === name);
			if (summary?.Id) {
				return this.wafV2.send(
					new GetWebACLCommand({ Name: name, Id: summary.Id, Scope: SCOPE }),
				);
			}
			nextMarker = page.NextMarker;
		} while (nextMarker);

		throw new Error(`Unknown WAF name ${name}`);
	}
}
