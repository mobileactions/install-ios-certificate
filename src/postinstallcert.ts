import sign = require('@mobileactions/ios-common');
import os = require('os');
import core = require('@actions/core');

async function run() {
    try {
        // Check platform is macOS since demands are not evaluated on Hosted pools
        if (os.platform() !== 'darwin') {
            console.log('InstallRequiresMac');
        } else {
            let removeProfile: boolean = core.getInput('removeProfile').trim().toLowerCase() === 'true';
            if (removeProfile) {
                let keychainPath: string | undefined = process.env['APPLE_CERTIFICATE_KEYCHAIN'];
                if (keychainPath) {
                    await sign.deleteKeychain(keychainPath);
                }
            }
        }
    } catch (err) {
        core.warning(err);
    }
}

run();