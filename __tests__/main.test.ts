import * as path from 'path'
import core = require('@actions/core');
const exec = require('@actions/exec');
import ios = require('../src/installcert');
import fs = require('fs');

test('Install signing certificate', async() => {
  fs.readFile(path.join(__dirname, "testcert.p12.base64"), "utf8", async (err, data) => {

    //Simulates file being stored as a GitHub secret
    core.exportVariable('INPUT_P12_CERTIFICATE', data);

    core.exportVariable('INPUT_KEYCHAIN', 'temp');
    core.exportVariable('INPUT_CERTPWD', 'theshakes');
    
    await ios.installSigningCertTask(); 

  });
})
