// Based on the cfn-response sources published by AWS at
// https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/cfn-lambda-function-code-cfnresponsemodule.html
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

import https from 'https';

export const SUCCESS = 'SUCCESS';
export const FAILED = 'FAILED';

export type ResponseStatus = typeof SUCCESS | typeof FAILED;

export interface CustomResourceRequest {
	RequestType: 'Create' | 'Update' | 'Delete';
	ServiceToken: string;
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
