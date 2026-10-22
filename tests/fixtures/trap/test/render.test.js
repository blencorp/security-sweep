'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { renderPage } = require('../src/render');

test('page includes the shared header', () => {
  const html = renderPage('Ada');
  assert.match(html, /<h1>Example<\/h1>/);
  assert.match(html, /Welcome, Ada\./);
});
