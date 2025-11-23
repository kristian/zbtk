import stylistic from '@stylistic/eslint-plugin';
import jsdoc from 'eslint-plugin-jsdoc';

export default [
  stylistic.configs.customize({
    flat: true,
    indent: 2,
    quotes: 'single',
    semi: true,
    jsx: false
  }),
  jsdoc.configs['flat/recommended-error'],
  {
    ignores: ['.pnp.cjs', '.pnp.loader.mjs', '.yarn/']
  },
  {
    'plugins': {
      jsdoc
    },
    'rules': {
      '@stylistic/comma-dangle': ['error', 'never'],
      '@stylistic/arrow-parens': ['error', 'as-needed'],
      '@stylistic/space-before-function-paren': ['error', {
        'anonymous': 'never',
        'named': 'never',
        'asyncArrow': 'always'
      }],
      '@stylistic/brace-style': ['error', '1tbs', { 'allowSingleLine': true }],
      '@stylistic/multiline-ternary': ['off'],
      '@stylistic/operator-linebreak': ['error', 'after'],
      '@stylistic/quote-props': ['error', 'consistent'],

      'jsdoc/require-jsdoc': ['error', { 'publicOnly': true }],
      'jsdoc/require-returns-type': ['error', { 'contexts': ['any'] }],
      'jsdoc/tag-lines': ['error', 'any', { 'startLines': 1 }],
      'jsdoc/no-defaults': ['off'],
      'jsdoc/reject-any-type': ['off']
    },
    'settings': {
      'jsdoc': {
        'preferredTypes': { 'Function': 'function' }
      }
    }
  }
];
