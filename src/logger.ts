export interface Logger {
	log(message: string, args?: Record<string, unknown>): void;
	debug(message: string, args?: Record<string, unknown>): void;
	warn(message: string, args?: Record<string, unknown>): void;
	error(message: string, args?: Record<string, unknown>): void;
}
