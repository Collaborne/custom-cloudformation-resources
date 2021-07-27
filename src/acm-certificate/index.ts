import { ACM, Route53 } from 'aws-sdk';

import type { SchemaType } from '@collaborne/json-schema-to-type';

import { CustomResource, Response } from '../custom-resource';
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
type EmailDomainValidationOption = SchemaType<
	typeof EMAIL_DOMAIN_VALIDATION_OPTION_SCHEMA
>;

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
type DNSDomainValidationOption = SchemaType<
	typeof DNS_DOMAIN_VALIDATION_OPTION_SCHEMA
>;

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
	const lastSlashIndex = certificateArn.lastIndexOf('/');
	return certificateArn.substring(lastSlashIndex + 1);
}

// XXX: The AWS::CertificateManager::Certificate uses the ARN as Ref, not an id (and then also doesn't have a .Arn attribute)
export class ACMCloudfrontCertificate extends CustomResource<
	ResourceAttributes,
	typeof SCHEMA
> {
	private acm = new ACM({ region: 'us-east-1' });
	private route53 = new Route53();

	constructor(logicalResourceId: string, logger: Logger) {
		super(SCHEMA, logicalResourceId, logger);
	}

	public async createResource(
		physicalResourceId: string,
		params: SchemaType<typeof SCHEMA>,
	): Promise<Response<ResourceAttributes>> {
		const attributes = await this.createCertificate(params);
		return {
			physicalResourceId: `${physicalResourceId}/${attributes.CertificateId}`,
			attributes,
		};
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
		await this.acm
			.deleteCertificate({ CertificateArn: certificateArn })
			.promise();

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
	): Promise<Response<ResourceAttributes>> {
		const {
			CertificateTransparencyLoggingPreference: ctLoggingPreference,
			Tags: tags = [],
		} = params;
		const changedAttributes = this.findChangedAttributes(params, oldParams);
		if (
			changedAttributes.length === 1 &&
			changedAttributes[0] === 'CertificateTransparencyLoggingPreference'
		) {
			// Update the preference
			const certificateArn = await this.findCertificateArn(
				physicalResourceId,
				params.DomainName,
			);
			if (!certificateArn) {
				throw new Error(
					`Cannot find certificate ${physicalResourceId} (domain ${params.DomainName})`,
				);
			}

			await this.acm
				.updateCertificateOptions({
					CertificateArn: certificateArn,
					Options: {
						CertificateTransparencyLoggingPreference: ctLoggingPreference,
					},
				})
				.promise();

			return {
				physicalResourceId,
				attributes: {
					Arn: certificateArn,
					CertificateId: getCertificateId(certificateArn),
				},
			};
		} else if (
			changedAttributes.length === 1 &&
			changedAttributes[0] === 'Tags'
		) {
			// Update tags
			const certificateArn = await this.findCertificateArn(
				physicalResourceId,
				params.DomainName,
			);
			if (!certificateArn) {
				throw new Error(
					`Cannot find certificate ${physicalResourceId} (domain ${params.DomainName})`,
				);
			}

			const { Tags: existingTags = [] } = await this.acm
				.listTagsForCertificate({ CertificateArn: certificateArn })
				.promise();
			const tagsToAdd: ACM.Tag[] = [];
			for (const tag of tags) {
				if (
					!existingTags.find(
						({ Key: k, Value: v }) => k === tag.Key && v === tag.Value,
					)
				) {
					tagsToAdd.push(tag);
				}
			}
			await this.acm
				.addTagsToCertificate({
					CertificateArn: certificateArn,
					Tags: tagsToAdd,
				})
				.promise();

			const tagsToRemove: ACM.Tag[] = [];
			for (const tag of existingTags) {
				if (
					!tags.find(({ Key: k, Value: v }) => k === tag.Key && v === tag.Value)
				) {
					tagsToRemove.push(tag);
				}
			}
			await this.acm
				.removeTagsFromCertificate({
					CertificateArn: certificateArn,
					Tags: tagsToRemove,
				})
				.promise();

			return {
				physicalResourceId,
				attributes: {
					Arn: certificateArn,
					CertificateId: getCertificateId(certificateArn),
				},
			};
		} else {
			// Replace the whole thing, and return a new resource id.
			// If the old physical resource id contains the old certificate id, replace that, otherwise it's a legacy
			// resource and we need to _add_ the id.
			const certificateArn = await this.findCertificateArn(
				physicalResourceId,
				params.DomainName,
			);
			if (!certificateArn) {
				throw new Error(
					`Cannot find certificate ${physicalResourceId} (domain ${params.DomainName})`,
				);
			}

			const newAttributes = await this.createCertificate(
				params,
				physicalResourceId,
			);

			// Note that we just return the new id, and CloudFormation will call us at the end to clean up.
			let physicalResourceIdPrefix;
			if (physicalResourceId.endsWith(`/${getCertificateId(certificateArn)}`)) {
				const lastSlashIndex = physicalResourceId.lastIndexOf('/');
				physicalResourceIdPrefix = physicalResourceId.substring(
					lastSlashIndex + 1,
				);
			} else {
				physicalResourceIdPrefix = physicalResourceId;
			}
			const newPhysicalResourceId = `${physicalResourceIdPrefix}/${newAttributes.CertificateId}`;
			this.logger.log(
				`Replaced certificate ${physicalResourceId} with ${newPhysicalResourceId}`,
			);
			return {
				physicalResourceId: newPhysicalResourceId,
				attributes: newAttributes,
			};
		}
	}

	private async findCertificateArn(
		physicalResourceId: string,
		domainName: string,
	): Promise<string | undefined> {
		async function listCertificates(
			acm: ACM,
			params: Pick<
				ACM.ListCertificatesRequest,
				'CertificateStatuses' | 'Includes'
			> = {},
		): Promise<ACM.CertificateSummary[]> {
			async function collect(
				knownCertificates: ACM.CertificateSummary[],
				token?: string,
			): Promise<ACM.CertificateSummary[]> {
				const {
					CertificateSummaryList: newCertificates = [],
					NextToken: nextToken,
				} = await acm
					.listCertificates({
						...params,
						NextToken: token,
					})
					.promise();

				const resources = [...knownCertificates, ...newCertificates];
				if (nextToken) {
					return collect(resources, nextToken);
				}
				return resources;
			}

			return collect([]);
		}

		const certificates = await listCertificates(this.acm);
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
	): Promise<ACM.ResourceRecord[]> {
		let interval: NodeJS.Timeout;
		let retries = 0;
		return new Promise<ACM.ResourceRecord[]>((resolve, reject) => {
			interval = setInterval(async () => {
				const { Certificate: certificate } = await this.acm
					.describeCertificate({ CertificateArn: certificateArn })
					.promise();
				if (!certificate) {
					reject(new Error(`Cannot find certificate ${certificateArn}`));
					return;
				}

				const dnsDomainValidationOptions = (
					certificate.DomainValidationOptions ?? []
				).filter(options => options.ValidationMethod === 'DNS');
				if (dnsDomainValidationOptions.length === 0) {
					// Consider this "fatal": There's no indication that this would ever appear on its own so far in the docs.
					reject(
						new Error(
							`Cannot find DNS domain validation option in certificate ${certificateArn}: ${JSON.stringify(
								certificate,
							)}`,
						),
					);
					return;
				}

				const resourceRecords = dnsDomainValidationOptions
					.map(option => option.ResourceRecord)
					.filter(isDefined);
				const missingResourceRecords =
					dnsDomainValidationOptions.length - resourceRecords.length;
				if (missingResourceRecords > 0) {
					this.logger.error(
						`Missing resource records in ${missingResourceRecords} DNS validation options in certificate ${certificateArn} after ${++retries} attempts: ${JSON.stringify(
							certificate,
						)}`,
					);
					return;
				}

				this.logger.log(
					`Found all validation resource records in certificate ${certificateArn}: ${JSON.stringify(
						resourceRecords,
					)}`,
				);
				resolve(resourceRecords);
			}, Number(process.env.SLS_AWS_MONITORING_FREQUENCY || 5000));
		}).finally(() => {
			clearInterval(interval);
		});
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
		// Remove all DNS validation options: These aren't supported by the ACM class itself, but rather we need to implement them manually.
		const emailDomainValidationOptions: EmailDomainValidationOption[] =
			domainValidationOptions.filter(isEmailDomainValidationOption);
		const dnsDomainValidationOptions: DNSDomainValidationOption[] =
			domainValidationOptions.filter(isDNSDomainValidationOption);
		// There must be at most one of these, and that one option must be using the same domain name
		if (
			dnsDomainValidationOptions.length > 1 ||
			(dnsDomainValidationOptions.length === 1 &&
				dnsDomainValidationOptions[0].DomainName !== params.DomainName)
		) {
			throw new Error('Invalid DNS domain validation options');
		}

		// Request the certificate
		const request: ACM.RequestCertificateRequest = {
			...baseRequest,
			IdempotencyToken: rawIdempotencyToken.replace(/[^\w]/g, '').slice(0, 32),
			DomainValidationOptions:
				emailDomainValidationOptions.length === 0
					? undefined
					: emailDomainValidationOptions,
			Options: {
				CertificateTransparencyLoggingPreference: ctLoggingPreference,
			},
		};
		const { CertificateArn: certificateArn } = await this.acm
			.requestCertificate(request)
			.promise();
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
			const resourceRecords = await this.getValidationResourceRecords(
				certificateArn,
			);
			const hostedZoneId = dnsDomainValidationOptions[0].HostedZoneId;
			const result = await this.route53
				.changeResourceRecordSets({
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
				})
				.promise();

			this.logger.log(`Route53 change set: ${result.ChangeInfo.Id}`);
		}

		// In theory we could proceed, as we have the ARN -- but this will just lead to failures downstream
		// as the certificate isn't necessarily issued yet.
		await this.acm
			.waitFor('certificateValidated', { CertificateArn: certificateArn })
			.promise();

		return {
			Arn: certificateArn,
			CertificateId: getCertificateId(certificateArn),
		};
	}

	private findChangedAttributes(
		params: SchemaType<typeof SCHEMA>,
		oldParams: unknown,
	): string[] {
		function isChanged(to: any, from: any): boolean {
			switch (typeof from) {
				case 'undefined':
					return typeof to !== 'undefined';
				case 'object':
					return (
						typeof to !== 'object' ||
						!Object.entries(from).reduce(
							(r, [k, v]) => r && !isChanged(to[k], v),
							true,
						)
					);
				default:
					if (Array.isArray(from)) {
						return (
							!Array.isArray(to) ||
							from.length !== to.length ||
							!from.reduce((r, k, i) => r && to[i] === k, true)
						);
					}
					return from !== to;
			}
		}

		return Object.keys(params).filter(key =>
			isChanged(params[key], (oldParams as Record<any, any>)[key]),
		);
	}
}
