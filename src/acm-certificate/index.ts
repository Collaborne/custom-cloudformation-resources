import { isDeepStrictEqual } from 'node:util';

import {
	ACMClient,
	AddTagsToCertificateCommand,
	DeleteCertificateCommand,
	DescribeCertificateCommand,
	ListTagsForCertificateCommand,
	RemoveTagsFromCertificateCommand,
	RequestCertificateCommand,
	UpdateCertificateOptionsCommand,
	paginateListCertificates,
	type CertificateTransparencyLoggingPreference,
	type ListCertificatesRequest,
	type RequestCertificateRequest,
	type ResourceRecord,
	type Tag,
} from '@aws-sdk/client-acm';
import {
	ChangeResourceRecordSetsCommand,
	Route53Client,
} from '@aws-sdk/client-route-53';
import type { SchemaType } from '@collaborne/json-schema-to-type';

import {
	ContinuationRequired,
	CustomResource,
	Response,
} from '../custom-resource';
import { Logger } from '../logger';
import { isDefined } from '../utils';

const EMAIL_DOMAIN_VALIDATION_OPTION_SCHEMA = {
	type: 'object' as const,
	properties: {
		DomainName: {
			type: 'string' as const,
		},
		ValidationDomain: {
			type: 'string' as const,
		},
	},
	required: ['DomainName' as const, 'ValidationDomain' as const],
};
interface EmailDomainValidationOption {
	DomainName: string;
	ValidationDomain: string;
}

const DNS_DOMAIN_VALIDATION_OPTION_SCHEMA = {
	type: 'object' as const,
	properties: {
		DomainName: {
			type: 'string' as const,
		},
		HostedZoneId: {
			type: 'string' as const,
		},
	},
	required: ['DomainName' as const, 'HostedZoneId' as const],
};
interface DNSDomainValidationOption {
	DomainName: string;
	HostedZoneId: string;
}

const SCHEMA = {
	type: 'object' as const,
	properties: {
		DomainName: {
			type: 'string' as const,
		},
		CertificateTransparencyLoggingPreference: {
			type: 'string' as const,
			enum: ['ENABLED', 'DISABLED'],
		},
		DomainValidationOptions: {
			type: 'array' as const,
			items: {
				oneOf: [
					EMAIL_DOMAIN_VALIDATION_OPTION_SCHEMA,
					DNS_DOMAIN_VALIDATION_OPTION_SCHEMA,
				] as const,
			},
		},
		Tags: {
			type: 'array' as const,
			items: {
				type: 'object' as const,
				properties: {
					Key: {
						type: 'string' as const,
					},
					Value: {
						type: 'string' as const,
					},
				},
				required: ['Key' as const],
			},
		},
	},
	additionalProperties: true as const,
	required: ['DomainName' as const],
};

interface ResourceAttributes {
	Arn: string;
	CertificateId: string;
}

function isEmailDomainValidationOption(
	option: EmailDomainValidationOption | DNSDomainValidationOption,
): option is EmailDomainValidationOption {
	return 'ValidationDomain' in option;
}

function isDNSDomainValidationOption(
	option: EmailDomainValidationOption | DNSDomainValidationOption,
): option is DNSDomainValidationOption {
	return 'HostedZoneId' in option;
}

function getCertificateId(certificateArn: string): string {
	return certificateArn.slice(certificateArn.lastIndexOf('/') + 1);
}

function delay(milliseconds: number): Promise<void> {
	return new Promise(resolve => setTimeout(resolve, milliseconds));
}

// XXX: The AWS::CertificateManager::Certificate uses the ARN as Ref, not an id (and then also doesn't have a .Arn attribute)
export class ACMCertificate extends CustomResource<
	ResourceAttributes,
	typeof SCHEMA,
	Response<ResourceAttributes>
> {
	private acm = new ACMClient({ region: 'us-east-1' });
	private route53 = new Route53Client({});

	constructor(logicalResourceId: string, logger: Logger) {
		super(SCHEMA, logicalResourceId, logger);
	}

	public async createResource(
		physicalResourceId: string,
		params: SchemaType<typeof SCHEMA>,
		continuationAttributes: Response<ResourceAttributes>,
	): Promise<
		| Response<ResourceAttributes>
		| ContinuationRequired<Response<ResourceAttributes>>
	> {
		let response: Response<ResourceAttributes>;
		if (continuationAttributes) {
			response = continuationAttributes;
		} else {
			const attributes = await this.createCertificate(params);
			response = {
				physicalResourceId: `${physicalResourceId}/${attributes.CertificateId}`,
				attributes,
			};
		}

		return this.maybeContinuation(response);
	}

	public async deleteResource(
		physicalResourceId: string,
		params: SchemaType<typeof SCHEMA>,
	): Promise<Response<ResourceAttributes>> {
		// XXX: If there are multiple, what would happen? How could we identify "the one"?
		const certificateArn = await this.findCertificateArn(
			physicalResourceId,
			params.DomainName,
		);
		if (!certificateArn) {
			throw new Error(
				`Cannot find certificate ${physicalResourceId} (domain ${params.DomainName})`,
			);
		}

		// Delete the certificate itself
		//
		// Note that we're not going to delete the Route53 entries now: If the deletion was "temporary" (for example due
		// to other stack failures that led to cleanups), the DNS records will be reusable for the next attempt.
		// This matches the behavior of the original AWS::ACM::Certificate resource; if needed we could make the deletion
		// optional as the information should be available in the certificate data.
		await this.acm.send(
			new DeleteCertificateCommand({ CertificateArn: certificateArn }),
		);

		return {
			physicalResourceId,
			attributes: {
				Arn: certificateArn,
				CertificateId: getCertificateId(certificateArn),
			},
		};
	}

	public async updateResource(
		physicalResourceId: string,
		params: SchemaType<typeof SCHEMA>,
		oldParams: unknown,
		continuationAttributes: Response<ResourceAttributes>,
	): Promise<
		| Response<ResourceAttributes>
		| ContinuationRequired<Response<ResourceAttributes>>
	> {
		if (continuationAttributes) {
			return this.maybeContinuation(continuationAttributes);
		}

		const {
			CertificateTransparencyLoggingPreference: ctLoggingPreference,
			Tags: rawTags = [],
		} = params;
		const tags = rawTags as Tag[];
		const changedAttributes = this.findChangedAttributes(params, oldParams);
		if (
			changedAttributes.length === 1 &&
			changedAttributes[0] === 'CertificateTransparencyLoggingPreference'
		) {
			// Update the preference
			const certificateArn = await this.requireCertificateArn(
				physicalResourceId,
				params.DomainName,
			);

			await this.acm.send(
				new UpdateCertificateOptionsCommand({
					CertificateArn: certificateArn,
					Options: {
						CertificateTransparencyLoggingPreference:
							ctLoggingPreference as CertificateTransparencyLoggingPreference,
					},
				}),
			);

			return {
				physicalResourceId,
				attributes: this.getAttributes(certificateArn),
			};
		} else if (
			changedAttributes.length === 1 &&
			changedAttributes[0] === 'Tags'
		) {
			// Update tags
			const certificateArn = await this.requireCertificateArn(
				physicalResourceId,
				params.DomainName,
			);

			const { Tags: existingTags = [] } = await this.acm.send(
				new ListTagsForCertificateCommand({ CertificateArn: certificateArn }),
			);
			const tagsToAdd: Tag[] = [];
			for (const tag of tags) {
				if (
					!existingTags.find(
						({ Key: k, Value: v }) => k === tag.Key && v === tag.Value,
					)
				) {
					tagsToAdd.push(tag);
				}
			}
			await this.acm.send(
				new AddTagsToCertificateCommand({
					CertificateArn: certificateArn,
					Tags: tagsToAdd,
				}),
			);

			const tagsToRemove: Tag[] = [];
			for (const tag of existingTags) {
				if (
					!tags.find(({ Key: k, Value: v }) => k === tag.Key && v === tag.Value)
				) {
					tagsToRemove.push(tag);
				}
			}
			await this.acm.send(
				new RemoveTagsFromCertificateCommand({
					CertificateArn: certificateArn,
					Tags: tagsToRemove,
				}),
			);

			return {
				physicalResourceId,
				attributes: this.getAttributes(certificateArn),
			};
		} else {
			// Replace the whole thing, and return a new resource id.
			// If the old physical resource id contains the old certificate id, replace that, otherwise it's a legacy
			// resource and we need to _add_ the id.
			const certificateArn = await this.requireCertificateArn(
				physicalResourceId,
				params.DomainName,
			);

			const newAttributes = await this.createCertificate(
				params,
				physicalResourceId,
			);

			// Note that we just return the new id, and CloudFormation will call us at the end to clean up.
			let physicalResourceIdPrefix;
			if (physicalResourceId.endsWith(`/${getCertificateId(certificateArn)}`)) {
				const lastSlashIndex = physicalResourceId.lastIndexOf('/');
				physicalResourceIdPrefix = physicalResourceId.substring(
					0,
					lastSlashIndex,
				);
			} else {
				physicalResourceIdPrefix = physicalResourceId;
			}
			const newPhysicalResourceId = `${physicalResourceIdPrefix}/${newAttributes.CertificateId}`;
			this.logger.log(
				`Replaced certificate ${physicalResourceId} with ${newPhysicalResourceId}`,
			);
			return this.maybeContinuation({
				physicalResourceId: newPhysicalResourceId,
				attributes: newAttributes,
			});
		}
	}

	private getAttributes(certificateArn: string): ResourceAttributes {
		return {
			Arn: certificateArn,
			CertificateId: getCertificateId(certificateArn),
		};
	}

	private async requireCertificateArn(
		physicalResourceId: string,
		domainName: string,
	): Promise<string> {
		const certificateArn = await this.findCertificateArn(
			physicalResourceId,
			domainName,
		);
		if (!certificateArn) {
			throw new Error(
				`Cannot find certificate ${physicalResourceId} (domain ${domainName})`,
			);
		}
		return certificateArn;
	}

	private async findCertificateArn(
		physicalResourceId: string,
		domainName: string,
	): Promise<string | undefined> {
		const listOptions: Pick<
			ListCertificatesRequest,
			'CertificateStatuses' | 'Includes'
		> = {};
		const certificates = [];
		for await (const page of paginateListCertificates(
			{ client: this.acm },
			listOptions,
		)) {
			certificates.push(...(page.CertificateSummaryList ?? []));
		}
		// Find the certificate that matches the domain, and ideally contains the id in the resource id.
		// For legacy certificate this isn't true, so we will accept any certificate (with a warning!)
		let certificate = certificates.find(c => {
			const certificateId = getCertificateId(c.CertificateArn!);
			// In theory the check for the endsWith is enough, and we don't need to look things up
			// by domain name.
			if (physicalResourceId.endsWith(`/${certificateId}`)) {
				if (c.DomainName !== domainName) {
					this.logger.warn(
						`Certificate ${c.CertificateArn} contains unexpected domain: ${c.DomainName} (should be ${domainName})`,
					);
				}
				return true;
			}
			return false;
		});

		if (!certificate) {
			this.logger.warn(
				`Cannot find certificate by id, falling back to search by domain name`,
			);
			certificate = certificates.find(c => c.DomainName === domainName);
		}
		return certificate?.CertificateArn;
	}

	/**
	 * Get the required resource records for validation
	 */
	/* Implementation note: This method is based on the observation that sometimes the resource record information seems
	 * to take a while to appear, so it will retry a couple of times if there are DNS validation options without resource
	 * records attached to it.
	 */
	private async getValidationResourceRecords(
		certificateArn: string,
	): Promise<ResourceRecord[]> {
		const pollingInterval = Number(
			process.env.SLS_AWS_MONITORING_FREQUENCY || 5000,
		);
		const maxAttempts = Number(
			process.env.SLS_AWS_MONITORING_MAX_ATTEMPTS || 60,
		);

		for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
			const { Certificate: certificate } = await this.acm.send(
				new DescribeCertificateCommand({ CertificateArn: certificateArn }),
			);
			if (!certificate) {
				throw new Error(`Cannot find certificate ${certificateArn}`);
			}

			this.logger.log(
				`getValidationResourceRecords certificate: ${JSON.stringify(
					certificate,
				)}`,
			);

			const dnsDomainValidationOptions = (
				certificate.DomainValidationOptions ?? []
			).filter(options => options.ValidationMethod === 'DNS');
			if (dnsDomainValidationOptions.length === 0) {
				// Consider this "fatal": There's no indication that this would ever appear on its own so far in the docs.
				throw new Error(
					`Cannot find DNS domain validation option in certificate ${certificateArn}: ${JSON.stringify(
						certificate,
					)}`,
				);
			}

			this.logger.log(
				`getValidationResourceRecords dnsDomainValidationOptions: ${JSON.stringify(
					dnsDomainValidationOptions,
				)}`,
			);

			const resourceRecords = dnsDomainValidationOptions
				.map(option => option.ResourceRecord)
				.filter(isDefined);
			this.logger.log(
				`getValidationResourceRecords resourceRecords: ${JSON.stringify(
					resourceRecords,
				)}`,
			);

			const missingResourceRecords =
				dnsDomainValidationOptions.length - resourceRecords.length;
			if (missingResourceRecords === 0) {
				this.logger.log(
					`Found all validation resource records in certificate ${certificateArn}: ${JSON.stringify(
						resourceRecords,
					)}`,
				);
				return resourceRecords;
			}

			this.logger.error(
				`Missing resource records in ${missingResourceRecords} DNS validation options in certificate ${certificateArn} after ${attempt} attempts: ${JSON.stringify(
					certificate,
				)}`,
			);
			if (attempt < maxAttempts) {
				await delay(pollingInterval);
			}
		}

		throw new Error(
			`Timed out waiting for DNS validation records for certificate ${certificateArn}`,
		);
	}

	private async createCertificate(
		params: SchemaType<typeof SCHEMA>,
		rawIdempotencyToken = `${this.logicalResourceId}-${Date.now()}`,
	): Promise<ResourceAttributes> {
		const {
			CertificateTransparencyLoggingPreference: ctLoggingPreference,
			DomainValidationOptions: domainValidationOptions = [],
			...baseRequest
		} = params;
		const validationOptions = domainValidationOptions as Array<
			EmailDomainValidationOption | DNSDomainValidationOption
		>;
		// Remove all DNS validation options: These aren't supported by the ACM class itself, but rather we need to implement them manually.
		const emailDomainValidationOptions: EmailDomainValidationOption[] = [];
		const dnsDomainValidationOptions: DNSDomainValidationOption[] = [];
		for (const option of validationOptions) {
			if (isEmailDomainValidationOption(option)) {
				emailDomainValidationOptions.push(option);
			} else if (isDNSDomainValidationOption(option)) {
				dnsDomainValidationOptions.push(option);
			}
		}
		// There must be at most one of these, and that one option must be using the same domain name
		if (
			dnsDomainValidationOptions.length > 1 ||
			(dnsDomainValidationOptions.length === 1 &&
				dnsDomainValidationOptions[0].DomainName !== params.DomainName)
		) {
			throw new Error('Invalid DNS domain validation options');
		}

		try {
			// Request the certificate
			const request: RequestCertificateRequest = {
				...baseRequest,
				IdempotencyToken: rawIdempotencyToken
					.replace(/[^\w]/g, '')
					.slice(0, 32),
				DomainValidationOptions:
					emailDomainValidationOptions.length === 0
						? undefined
						: emailDomainValidationOptions,
				Options: {
					CertificateTransparencyLoggingPreference:
						ctLoggingPreference as CertificateTransparencyLoggingPreference,
				},
			};
			const { CertificateArn: certificateArn } = await this.acm.send(
				new RequestCertificateCommand(request),
			);
			if (!certificateArn) {
				// Hopefully some hints are in Cloudtrail now ...
				throw new Error(
					'Failed to request certificate: No certificate ARN returned',
				);
			}

			// We have an ARN, so at least all initial parameters were good enough. Proceed working on the validation ...
			this.logger.log(`Certificate requested: ${certificateArn}`);

			// If validation was supposed to happen via email, or there are no options provided for DNS validation, then we're
			// done and the caller knows what to do.
			// Otherwise we need to go to Route53 and upsert the needed RR there.
			if (dnsDomainValidationOptions.length !== 0) {
				this.logger.log('Validation is DNS Domain Validation');
				const resourceRecords =
					await this.getValidationResourceRecords(certificateArn);
				this.logger.log(`resourceRecords: ${JSON.stringify(resourceRecords)}`);
				const hostedZoneId = dnsDomainValidationOptions[0].HostedZoneId;
				this.logger.log(`hostedZoneId: ${hostedZoneId}`);
				const result = await this.route53.send(
					new ChangeResourceRecordSetsCommand({
						HostedZoneId: hostedZoneId,
						ChangeBatch: {
							Changes: resourceRecords.map(resourceRecord => ({
								Action: 'UPSERT',
								ResourceRecordSet: {
									Name: resourceRecord.Name,
									Type: resourceRecord.Type,
									// The TTL can in theory be very large, but that would potentially hinder our ability
									// to quickly revoke a certificate. As there shouldn't be many requests to this either, 300
									// should be just fine.
									TTL: 300,
									ResourceRecords: [
										{
											Value: resourceRecord.Value,
										},
									],
								},
							})),
						},
					}),
				);

				this.logger.log(`Route53 change set: ${result.ChangeInfo?.Id}`);
			}

			return {
				Arn: certificateArn,
				CertificateId: getCertificateId(certificateArn),
			};
		} catch (error) {
			this.logger.error(error instanceof Error ? error.message : String(error));

			throw error;
		}
	}

	private findChangedAttributes(
		params: SchemaType<typeof SCHEMA>,
		oldParams: unknown,
	): string[] {
		return Object.keys(params).filter(
			key =>
				!isDeepStrictEqual(
					(params as Record<string, unknown>)[key],
					(oldParams as Record<string, unknown>)[key],
				),
		);
	}

	protected async maybeContinuation(
		response: Response<ResourceAttributes>,
	): Promise<
		| Response<ResourceAttributes>
		| ContinuationRequired<Response<ResourceAttributes>>
	> {
		// Initially wee have the id in the response, so we simply check now whether the certificate is valid.
		// If it is, great, return the response. Otherwise stuff the whole response into continuationAttributes, and
		// try again in a minute or two.
		const certificateArn = response.attributes?.Arn;
		if (!certificateArn) {
			throw new Error('Missing certificate ARN');
		}

		const { Certificate: certificate } = await this.acm.send(
			new DescribeCertificateCommand({ CertificateArn: certificateArn }),
		);
		if (!certificate) {
			throw new Error(`Cannot find certificate ${certificateArn}`);
		}

		if (certificate.Status === 'ISSUED') {
			this.logger.log('Certificate is ISSUED, stopping continuations');
			return response;
		} else if (certificate.Status === 'PENDING_VALIDATION') {
			this.logger.log(
				`Certificate is PENDING_VALIDATION, requesting continuation`,
			);
			return {
				continuationAfter: Number(process.env.RETRY_INTERVAL_SECONDS ?? '300'),
				continuationAttributes: response,
			};
		} else {
			throw new Error(`Certificate is in invalid status ${certificate.Status}`);
		}
	}
}
