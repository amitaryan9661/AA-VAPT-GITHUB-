const fs = require('fs');
const vm = require('vm');

const html = fs.readFileSync('webapp-pt.html', 'utf8');

const scriptStart = html.indexOf('// ── On-screen error banner');
const beforeBanner = html.lastIndexOf('<script>', scriptStart);
const scriptEnd = html.lastIndexOf('</script>');
const jsCode = html.substring(beforeBanner + '<script>'.length, scriptEnd);

console.log('JS code length:', jsCode.length, 'characters');

try {
  new vm.Script(jsCode, { filename: 'webapp-pt.js' });
  console.log('✅ NO SYNTAX ERRORS - Compiled successfully in VM!');
} catch (e) {
  console.log('❌ SYNTAX ERROR:');
  console.log('Message:', e.message);
  console.log('Stack:', e.stack.split('\n').slice(0, 5).join('\n'));
}
