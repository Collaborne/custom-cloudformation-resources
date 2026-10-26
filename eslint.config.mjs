import createCollaborneConfig from 'eslint-config-collaborne';

export default [
	...createCollaborneConfig({
		tsconfigRootDir: import.meta.dirname,
		project: ['./tsconfig.json'],
	}),
	{ ignores: ['dist/**', 'node_modules/**'] },
	{
		files: ['src/**/*.ts'],
		rules: {
			'max-lines': 'off',
			'@typescript-eslint/naming-convention': 'off',
			'@typescript-eslint/no-unnecessary-type-constraint': 'off',
		},
	},
];
