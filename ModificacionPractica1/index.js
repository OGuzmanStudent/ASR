const html_to_pdf = require('html-pdf-node');
const fs = require('fs');


// Example of options with args //
// let options = { format: 'A4', args: ['--no-sandbox', '--disable-setuid-sandbox'] };
const myArgs = process.argv[2];
console.log('myArgs: ', myArgs);

const options = { format: 'A4', path:'./report.pdf' };


//let rawdata = fs.readFileSync('student.json');
//let student = JSON.parse(rawdata);
let file = { content: "<h1>Welcome to html-pdf-node</h1>" };
html_to_pdf.generatePdf(file, options);
