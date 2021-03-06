// Based on the cfn-response sources published by AWS at
// https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/cfn-lambda-function-code-cfnresponsemodule.html
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

import https from 'https';

export const SUCCESS = 'SUCCESS';
export const FAILED = 'FAILED';

export type ResponseStatus = typeof SUCCESS | typeof FAILED;

/**
 * See <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/crpg-ref-requests.html>
 */
export interface CustomResourceRequest {
	/**
	 * The service token used for actually invoking the handler
	 *
	 * Note: This field is not documented by AWS, but it is visible both in dumps and other blog posts/medium articles.
	 */
	ServiceToken: string;
	RequestType: 'Create' | 'Update' | 'Delete';
	ResponseURL: string;
	StackId: string;
	RequestId: string;
	LogicalResourceId: string;
	PhysicalResourceId: string;
	ResourceType: string;
	ResourceProperties: {
		ServiceToken: string;
		[k: string]: unknown;
	};
	OldResourceProperties?: {
		ServiceToken: string;
		[k: string]: unknown;
	};
}

export function send(
	request: CustomResourceRequest,
	responseStatus: ResponseStatus,
	responseReason?: string,
	physicalResourceId?: string,
	responseData: unknown = {},
	noEcho = false,
): Promise<void> {
	const responseBody = JSON.stringify({
		Status: responseStatus,
		Reason:
			responseReason ||
			(responseStatus === 'FAILED' ? 'Unknown error' : undefined),
		PhysicalResourceId: physicalResourceId || request.PhysicalResourceId,
		StackId: request.StackId,
		RequestId: request.RequestId,
		LogicalResourceId: request.LogicalResourceId,
		NoEcho: noEcho,
		Data: responseData,
	});
	if (responseBody.length >= 4096) {
		// Warn, but proceed. The problem is that at this point we cannot do anything anymore -- CF will fail, and will do
		// rollbacks as needed.
		// We do log the complete body here, so that the operator/developer hopefully sees what can be shortened.
		// See https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/crpg-ref-responses.html#crpg-ref-responses-fields
		console.warn(
			`Response body length of ${responseBody.length} bytes exceeds CloudFormation limit of 4KiB: ${responseBody}`,
		);
	}

	const options = {
		method: 'PUT',
		headers: {
			'content-type': 'application/json',
			'content-length': responseBody.length,
		},
	};

	return new Promise<void>((resolve, reject) => {
		function logProblem(message: string) {
			// Provide enough detail here so that a human could possibly fix the situation using curl.
			console.error(
				`Failed to report status '${responseBody}' to '${request.ResponseURL}': ${message}`,
			);
		}

		const req = https.request(request.ResponseURL, options, res => {
			if (!res.statusCode || res.statusCode >= 400) {
				const message = `Unexpected status code ${res.statusCode}`;
				logProblem(message);
				reject(new Error(message));
				return;
			}
			resolve();
		});

		req.on('error', err => {
			logProblem(err.message);
			reject(err);
		});

		req.write(responseBody);
		req.end();
	});
}
