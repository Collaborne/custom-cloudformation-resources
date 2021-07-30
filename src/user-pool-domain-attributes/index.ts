import { CognitoIdentityServiceProvider } from 'aws-sdk';

import { SchemaType } from '@collaborne/json-schema-to-type';

import { CustomResource, Response } from '../custom-resource';
import { Logger } from '../logger';

const SCHEMA = {
	type: 'object' as const,
	properties: {
		UserPoolDomain: {
			type: 'string' as const,
		},
	},
	required: ['UserPoolDomain' as const],
};

type ResourceAttributes = Pick<
	CognitoIdentityServiceProvider.DomainDescriptionType,
	'CloudFrontDistribution'
>;

export class UserPoolDomainAttributes extends CustomResource<
	ResourceAttributes,
	typeof SCHEMA
> {
	private cognitoIdp = new CognitoIdentityServiceProvider();

	constructor(logicalResourceId: string, logger: Logger) {
		super(SCHEMA, logicalResourceId, logger);
	}

	public async createResource(
		physicalResourceId: string,
		{ UserPoolDomain: userPoolDomain }: SchemaType<typeof SCHEMA>,
	): Promise<Response<ResourceAttributes>> {
		const attributes = await this.getAttributes(userPoolDomain);
		return {
			physicalResourceId,
			attributes,
		};
	}

	public async deleteResource(
		physicalResourceId: string,
	): Promise<Response<ResourceAttributes>> {
		return {
			physicalResourceId,
		};
	}

	public async updateResource(
		physicalResourceId: string,
		{ UserPoolDomain: userPoolDomain }: SchemaType<typeof SCHEMA>,
	): Promise<Response<ResourceAttributes>> {
		const attributes = await this.getAttributes(userPoolDomain);
		return {
			physicalResourceId,
			attributes,
		};
	}

	protected async getAttributes(
		userPoolDomain: string,
	): Promise<ResourceAttributes> {
		const response = await this.cognitoIdp
			.describeUserPoolDomain({
				Domain: userPoolDomain,
			})
			.promise();
		if (!response.DomainDescription) {
			throw new Error(`Unknown Cognito user pool domain ${userPoolDomain}`);
		}
		return response.DomainDescription;
	}
}
