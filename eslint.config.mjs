import pluginJs from '@eslint/js'
import tseslint from 'typescript-eslint'
import antiTrojanSource from 'eslint-plugin-anti-trojan-source'

export default [
    { files: ['**/*.{js,mjs,cjs,ts}'] },
    { files: ['**/*.js'], languageOptions: { sourceType: 'commonjs' } },

    pluginJs.configs.recommended,
    ...tseslint.configs.recommended,
    {
        plugins: { 'anti-trojan-source': antiTrojanSource },
        rules: { 'anti-trojan-source/no-bidi': 'error' },
    },
    {
        rules: {
            'no-console': ['error', { allow: ['warn', 'error'] }],
            '@typescript-eslint/no-unused-vars': [
                'error',
                {
                    ignoreRestSiblings: true,
                    varsIgnorePattern: '_+',
                    argsIgnorePattern: '^_',
                },
            ],
            semi: ['error', 'never'],
        },
    },
]
