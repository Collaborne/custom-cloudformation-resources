export function isDefined<T>(o: T | undefined): o is T {
	return typeof o !== 'undefined';
}
