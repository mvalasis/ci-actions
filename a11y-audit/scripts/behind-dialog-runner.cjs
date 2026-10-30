// A pa11y runner for a11y-audit's second pass: page-has-heading-one and landmark-one-main graded on the
// page, not its banner. axe passes both unread while a modal is open (`passForModal: true`, its own
// check option): any open dialog, or a fixed box over 75% of the viewport. So this pass switches that
// off, and removes the open dialogs so a heading inside one cannot stand in for the page's. Removing
// them for the main pass would hide a real dialog's own findings, hence a runner of its own, on a load
// of its own. pa11y loads this by absolute path; its `run` is serialized into the page, so it can
// reach nothing out here.
'use strict';
const fs = require('node:fs');
const path = require('node:path');

// axe-core sits in the install's private dir with pa11y-ci, never beside this file.
const axe = require.resolve('axe-core/axe.min.js', { paths: [path.dirname(fs.realpathSync(process.argv[1]))] });

const run = async () => {
  const SELECTOR = 'dialog[open], [role=dialog], [aria-modal=true]';
  const open = [...document.querySelectorAll(SELECTOR)];
  open.forEach((el) => el.remove());
  // isModalOpen reads axe's flattened tree, which exists only between setup and teardown.
  window.axe.setup();
  const modal = window.axe.commons.dom.isModalOpen();
  window.axe.teardown();
  const state = open.length ? `${open.length} open dialog(s) removed` : modal ? 'a viewport-sized overlay left in place' : 'no dialog open';
  const check = (id) => window.axe.utils.clone(window.axe._audit.checks[id].options);
  window.axe.configure({ checks: ['page-has-heading-one', 'page-has-main'].map((id) => ({ id, options: { ...check(id), passForModal: false } })) });
  const r = await window.axe.run(document, { runOnly: { type: 'rule', values: ['page-has-heading-one', 'landmark-one-main'] } });
  return r.violations.map((v) => ({ code: v.id, message: `${v.help} (graded with ${state})`, type: 'error', element: document.documentElement }));
};

module.exports = { scripts: [axe], supports: '^10.0.0', run };
