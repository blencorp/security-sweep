'use strict';

const path = require('path');
const ejs = require('ejs');
const minimist = require('minimist');

const VIEWS = path.join(__dirname, '..', 'views');

function renderPage(name) {
  const file = path.join(VIEWS, 'page.ejs');
  const template = require('fs').readFileSync(file, 'utf8');
  return ejs.render(template, { name }, { filename: file });
}

if (require.main === module) {
  const args = minimist(process.argv.slice(2));
  process.stdout.write(renderPage(args.name || 'world') + '\n');
}

module.exports = { renderPage };
