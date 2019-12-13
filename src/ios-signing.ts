import path = require('path');
import core = require('@actions/core');
import io = require('@actions/io');
const exec = require('@actions/exec');
import execint from '@actions/exec/lib/interfaces'
import ioutils = require('./io-utils');

/**
 * Creates a temporary keychain and installs the P12 cert in the temporary keychain
 * @param keychainPath the path to the keychain file
 * @param keychainPwd the password to use for unlocking the keychain
 * @param p12CertPath the P12 cert to be installed in the keychain
 * @param p12Pwd the password for the P12 cert
 * @param useKeychainIfExists Pass false to delete and recreate a preexisting keychain
 */
export async function installCertInTemporaryKeychain(keychainPath: string, keychainPwd: string, p12CertPath: string, p12Pwd: string, useKeychainIfExists: boolean): Promise<void> {
    let setupKeychain: boolean = true;

    if (useKeychainIfExists && ioutils.exists(keychainPath)) {
        setupKeychain = false;
    }

    let securityCmd = await io.which('security', true);

    if (setupKeychain) {
        //delete keychain if exists
        await deleteKeychain(keychainPath);

        //create keychain
        await exec.exec(securityCmd, ['create-keychain', '-p', keychainPwd, keychainPath]);

        //update keychain settings, keep keychain unlocked for 6h = 21600 sec, which is the job timeout for paid hosted VMs
        await exec.exec(securityCmd, ['set-keychain-settings', '-lut', '21600', keychainPath]);
    }

    //unlock keychain
    await unlockKeychain(keychainPath, keychainPwd);

    //import p12 cert into the keychain
    if (!p12Pwd) {
        // if password is null or not defined, set it to empty
        p12Pwd = '';
    }
    await exec.exec(securityCmd, ['import', p12CertPath, '-P', p12Pwd, '-A', '-t', 'cert', '-f', 'pkcs12', '-k', keychainPath]);
    
    //If we imported into a pre-existing keychain (e.g. login.keychain), set the partition_id ACL for the private key we just imported
    //so codesign won't prompt to use the key for signing. This isn't necessary for temporary keychains, at least on High Sierra.
    //See https://stackoverflow.com/questions/39868578/security-codesign-in-sierra-keychain-ignores-access-control-settings-and-ui-p
    if (!setupKeychain) {
        const privateKeyName: string = await getP12PrivateKeyName(p12CertPath, p12Pwd);
        await setKeyPartitionList(keychainPath, keychainPwd, privateKeyName);
    }

    //list the keychains to get current keychains in search path
    let listAllOutput: string | undefined;
    const listAllOpts : execint.ExecOptions = {};
    listAllOpts.listeners = {
        stdout: (data: Buffer) => {
            if (data) {
                if (listAllOutput) {
                    listAllOutput = listAllOutput.concat(data.toString().trim());
                } else {
                    listAllOutput = data.toString().trim();
                }
            }
        }
    };
    await exec.exec(securityCmd, ['list-keychain', '-d', 'user'], listAllOpts);


    let allKeychainsArr: string[] = [];
    core.debug('listAllOutput = ' + listAllOutput);

    //parse out all the existing keychains in search path
    if (listAllOutput) {
        allKeychainsArr = listAllOutput.split(/[\n\r\f\v]/gm);
    }

    //add the keychain to list path along with existing keychains if it is not in the path
    if (listAllOutput && listAllOutput.indexOf(keychainPath) < 0) {
        let listAddArgs = ['list-keychain', '-d', 'user', '-s', keychainPath];
        for (var i: number = 0; i < allKeychainsArr.length; i++) {
            listAddArgs.push(allKeychainsArr[i].trim().replace(/"/gm, ''));
        }
        await exec.exec(securityCmd, listAddArgs);
    }

    let listVerifyOutput: string | undefined;
    const listVerifyOpts : execint.ExecOptions = {};
    listVerifyOpts.listeners = {
        stdout: (data: Buffer) => {
            if (data) {
                if (listVerifyOutput) {
                    listVerifyOutput = listVerifyOutput.concat(data.toString().trim());
                } else {
                    listVerifyOutput = data.toString().trim();
                }
            }
        }
    };
    await exec.exec(securityCmd, ['list-keychain', '-d', 'user'], listVerifyOpts);

    if (!listVerifyOutput || listVerifyOutput.indexOf(keychainPath) < 0) {
        throw ('TempKeychainSetupFailed');
    }
}

/**
 * Finds an iOS codesigning identity in the specified keychain
 * @param keychainPath
 * @returns {string} signing identity found
 */
export async function findSigningIdentity(keychainPath: string) {
    let signIdentity: string | undefined;
    let securityCmd = await io.which('security', true); 

    const findIdentityOpts : execint.ExecOptions = {};
    findIdentityOpts.listeners = {
        stdout: (data: Buffer) => {
            if (data) {
                let matches = data.toString().trim().match(/"(.+)"/g);
                core.debug('signing identity data = ' + matches);
                if (matches && matches[0]) {
                    signIdentity = matches[0].replace(/"/gm, '');
                    core.debug('signing identity data trimmed = ' + signIdentity);
                }
            }
        }
    };
    await exec.exec(securityCmd, ['find-identity', '-v', '-p', 'codesigning', keychainPath], findIdentityOpts);

    if (signIdentity) {
        core.debug('findSigningIdentity = ' + signIdentity);
        return signIdentity;
    } else {
        throw ('SignIdNotFound');
    }
}

/**
 * Get Cloud entitlement type Production or Development according to the export method - if entitlement doesn't exists in provisioning profile returns null
 * @param provisioningProfilePath
 * @param exportMethod
 * @returns {string}
 */
export async function getCloudEntitlement(provisioningProfilePath: string, exportMethod: string): Promise<string | null> {
    //find the provisioning profile details
    let tmpPlist = '_xcodetasktmp.plist';
    await saveProvisioningProfileDetails(provisioningProfilePath, tmpPlist);

    //use PlistBuddy to figure out if cloud entitlement exists.
    const cloudEntitlement = await execPlistBuddyCommand('Print Entitlements:com.apple.developer.icloud-container-environment', tmpPlist);

    //delete the temporary plist file
    await io.rmRF(tmpPlist);

    if (!cloudEntitlement) {
        return null;
    }

    core.debug('Provisioning Profile contains cloud entitlement');
    return (exportMethod === 'app-store' || exportMethod === 'enterprise' || exportMethod === 'developer-id')
                ? "Production"
                : "Development";
}



/**
 * Find the UUID and Name of the provisioning profile and install the profile
 * @param provProfilePath
 * @returns { provProfileUUID, provProfileName }
 */
export async function installProvisioningProfile(provProfilePath: string) : Promise<{ provProfileUUID: string, provProfileName: string}> {
    //find the provisioning profile UUID
    let tmpPlist = '_xcodetasktmp.plist';
    await saveProvisioningProfileDetails(provProfilePath, tmpPlist);

    //use PlistBuddy to figure out the UUID and Name
    let provProfileUUID = await execPlistBuddyCommand('Print UUID', tmpPlist);
    let provProfileName = await execPlistBuddyCommand('Print Name', tmpPlist);

    //delete the temporary plist file
    await io.rmRF(tmpPlist);

    if (provProfileUUID) {
        //copy the provisioning profile file to ~/Library/MobileDevice/Provisioning Profiles
        io.mkdirP(getUserProvisioningProfilesPath()); // Path may not exist if Xcode has not been run yet.
        core.debug('created directory: ' + getUserProvisioningProfilesPath());

        let pathToProvProfile: string = getProvisioningProfilePath(provProfileUUID, provProfilePath);

        core.debug('copying provisioning profile to destination: ' + pathToProvProfile);
        let cpCmd = await io.which('cp', true);
        let cpArgs = ['-f', provProfilePath, pathToProvProfile];
        await exec.exec(cpCmd, cpArgs);

        if (!provProfileName) {
            core.warning('ProvProfileNameNotFound');
            provProfileName = '';
        }

        return { provProfileUUID, provProfileName };
    } else {
        throw new Error('ProvProfileUUIDNotFound: ' + provProfilePath);
    }
}

/**
 * Find the Name of the provisioning profile
 * @param provProfilePath
 * @returns {string} Name
 */
export async function getProvisioningProfileName(provProfilePath: string) {
    //find the provisioning profile UUID
    let tmpPlist = '_xcodetasktmp.plist';
    let provProfileDetails = await saveProvisioningProfileDetails(provProfilePath, tmpPlist);

    //use PlistBuddy to figure out the Name
    let provProfileName = await execPlistBuddyCommand('Print Name', tmpPlist);

    //delete the temporary plist file
    await io.rmRF(tmpPlist);

    core.debug('getProvisioningProfileName: profile name = ' + provProfileName);
    return provProfileName;
}

/**
 * Find the type of the iOS provisioning profile - app-store, ad-hoc, enterprise or development
 * @param provProfilePath
 * @returns {string} type
 */
export async function getiOSProvisioningProfileType(provProfilePath: string) {
    let provProfileType: string | undefined;
    try {
        //find the provisioning profile details
        let tmpPlist = '_xcodetasktmp.plist';
        await saveProvisioningProfileDetails(provProfilePath, tmpPlist);

        //get ProvisionsAllDevices - this will exist for enterprise profiles
        let provisionsAllDevices = await execPlistBuddyCommand('Print ProvisionsAllDevices', tmpPlist);
        core.debug('provisionsAllDevices = ' + provisionsAllDevices);

        if (provisionsAllDevices && provisionsAllDevices.trim().toLowerCase() === 'true') {
            //ProvisionsAllDevices = true in enterprise profiles
            provProfileType = 'enterprise';
        } else {
            let getTaskAllow = await execPlistBuddyCommand('Print Entitlements:get-task-allow', tmpPlist);
            core.debug('getTaskAllow = ' + getTaskAllow);

            if (getTaskAllow && getTaskAllow.trim().toLowerCase() === 'true') {
                //get-task-allow = true means it is a development profile
                provProfileType = 'development';
            } else {
                let provisionedDevices = await execPlistBuddyCommand('Print ProvisionedDevices', tmpPlist);
                core.debug('provisionedDevices = ' + provisionedDevices);
                
                if (!provisionedDevices) {
                    // no provisioned devices for non-development profile means it is an app-store profile
                    provProfileType = 'app-store';
                } else {
                    // non-development profile with provisioned devices - use ad-hoc
                    provProfileType = 'ad-hoc';
                }
            }
        }

        //delete the temporary plist file
        await io.rmRF(tmpPlist);
        
    } catch (err) {
        core.debug(err);
    }

    return provProfileType;
}

/**
 * Find the type of the macOS provisioning profile - app-store, developer-id or development.
 * mac-application is a fourth macOS export method, but it doesn't include signing.
 * @param provProfilePath
 * @returns {string} type
 */
export async function getmacOSProvisioningProfileType(provProfilePath: string) {
    let provProfileType: string | undefined;
    try {
        //find the provisioning profile details
        let tmpPlist = '_xcodetasktmp.plist';
        await saveProvisioningProfileDetails(provProfilePath, tmpPlist);

        //get ProvisionsAllDevices - this will exist for developer-id profiles
        let provisionsAllDevices = await execPlistBuddyCommand('Print ProvisionsAllDevices', tmpPlist);
        core.debug('provisionsAllDevices = ' + provisionsAllDevices);

        if (provisionsAllDevices && provisionsAllDevices.trim().toLowerCase() === 'true') {
            //ProvisionsAllDevices = true in developer-id profiles
            provProfileType = 'developer-id';
        } else {
            let provisionedDevices = await execPlistBuddyCommand('Print ProvisionedDevices', tmpPlist);
            if (!provisionedDevices) {
                // no provisioned devices means it is an app-store profile
                provProfileType = 'app-store';
            } else {
                // profile with provisioned devices - use development
                provProfileType = 'development';
            }
        }

        //delete the temporary plist file
        await io.rmRF(tmpPlist);
        
    } catch (err) {
        core.debug(err);
    }

    return provProfileType;
}


/**
 * Unlock specified iOS keychain
 * @param keychainPath
 * @param keychainPwd
 */
export async function unlockKeychain(keychainPath: string, keychainPwd: string): Promise<void> {
    //unlock the keychain
    let unlockCommand = await io.which('security', true); 
    await exec.exec(unlockCommand, ['unlock-keychain', '-p', keychainPwd, keychainPath]);
}

/**
 * Delete specified iOS keychain
 * @param keychainPath
 */
export async function deleteKeychain(keychainPath: string): Promise<void> {
    if (ioutils.exists(keychainPath)) {
        let deleteKeychainCommand = await io.which('security', true);
        await exec.exec(deleteKeychainCommand, ['delete-keychain', keychainPath]);
    }
}

/**
 * Delete provisioning profile with specified UUID in the user's profiles directory
 * @param uuid
 */
export async function deleteProvisioningProfile(uuid: string): Promise<void> {
    if (uuid && uuid.trim()) {
        let findCmd = await io.which('ls', true);
        let provProfilesDir = getUserProvisioningProfilesPath();
        let findArgs = ['-1', provProfilesDir + '/' + uuid.trim() + '*'];
        const findOpts : execint.ExecOptions = {};
        findOpts.listeners = {
            stdline: async (data: string) => {
                let profPath = provProfilesDir + '/' + data;
                if (ioutils.exists(profPath)) {
                    console.log('Deleting provisioning profile: ' + profPath);
                    await io.rmRF(profPath);
                }
            }
        };
        await exec.exec(findCmd, findArgs, findOpts);
    }
}

/**
 * Gets the path to the iOS default keychain
 */
export async function getDefaultKeychainPath() {
    let defaultKeychainPath: string = '';
    let getKeychainCmd = await io.which('security', true); 
    const getKeyChainOpts : execint.ExecOptions = {};
    getKeyChainOpts.listeners = {
        stdout: (data: Buffer) => {
            if (data) {
                defaultKeychainPath = data.toString().trim().replace(/[",\n\r\f\v]/gm, '');
                if (!ioutils.exists(defaultKeychainPath)) {
                    throw new Error('Received invalid default keychain path.');
                }
            }
        }
    };
    await exec.exec(getKeychainCmd, ['default-keychain'], getKeyChainOpts);

    return defaultKeychainPath;
}

/**
 * Gets the path to the temporary keychain path used during build or release
 */
export function getTempKeychainPath(): string {
    let keychainName: string = 'ios_signing_temp.keychain';
    let getTempKeychainPath: string = path.resolve('/tmp', keychainName);
    return getTempKeychainPath;
}

/**
 * Get several x509 properties from the certificate in a P12 file.
 * @param p12Path Path to the P12 file
 * @param p12Pwd Password for the P12 file
 */
export async function getP12Properties(p12Path: string, p12Pwd: string): Promise<{ fingerprint: string | undefined, commonName: string | undefined, notBefore: Date | undefined, notAfter: Date | undefined}> {
    //openssl pkcs12 -in <p12Path> -nokeys -passin pass:"<p12Pwd>" | openssl x509 -noout -fingerprint –subject -dates    
    let output = '';

    if (!p12Pwd) {
        // if password is null or not defined, set it to empty
        p12Pwd = '';
    }

    let fingerprint: string | undefined;
    let commonName: string | undefined;
    let notBefore: Date | undefined;
    let notAfter: Date | undefined;

    function onLine(line: string) {
        if (line) {
            const tuple = splitIntoKeyValue(line);
            const key: string = (tuple) ? tuple.key : '';
            const value: string = (tuple) ? tuple.value : '';

            if (key === 'SHA1 Fingerprint') {
                // Example value: "BB:26:83:C6:AA:88:35:DE:36:94:F2:CF:37:0A:D4:60:BB:AE:87:0C"
                // Remove colons separating each octet.
                fingerprint = value.replace(/:/g, '').trim();
            } else if (key === 'subject') {
                // Example value: "/UID=E848ASUQZY/CN=iPhone Developer: Chris Sidi (7RZ3N927YF)/OU=DJ8T2973U7/O=Chris Sidi/C=US"
                // Extract the common name.
                const matches: string[] | null = value.match(/\/CN=([^/]+)/);
                if (matches && matches[1]) {
                    commonName = matches[1].trim();
                }
            } else if (key === 'notBefore') {
                // Example value: "Nov 13 03:37:42 2018 GMT"
                notBefore = new Date(value);
            } else if (key === 'notAfter') {
                notAfter = new Date(value);
            }
        }
    }


    let opensslcmd: string = await io.which('openssl', true);
    await exec.exec(opensslcmd, ['pkcs12', '-in', p12Path, '-out', '/tmp/step1.openssl', '-nokeys', '-passin', 'pass:' + p12Pwd]);

    const opensslopts : execint.ExecOptions = {};
    opensslopts.listeners = {
        stdout: (data: Buffer) => {
            output = output + data.toString();
        }
    };

    try {
        await exec.exec(opensslcmd, ['x509', '-in', '/tmp/step1.openssl', '-noout', '-fingerprint', '-subject', '-dates'], opensslopts);

        // process the collected stdout.
        let line: string;
        for (line of output.split('\n')) {
            onLine(line);
        }
    } catch (err) {
        if (!p12Pwd) {
            core.warning('NoP12PwdWarning');
        }
        throw err;
    }

    core.debug(`P12 fingerprint: ${fingerprint}`);
    core.debug(`P12 common name (CN): ${commonName}`);
    core.debug(`NotBefore: ${notBefore}`);
    core.debug(`NotAfter: ${notAfter}`);

    return { fingerprint, commonName, notBefore, notAfter };
}

/**
 * Get the friendly name from the private key in a P12 file.
 * @param p12Path Path to the P12 file
 * @param p12Pwd Password for the P12 file
 */
export async function getP12PrivateKeyName(p12Path: string, p12Pwd: string): Promise<string> {
    //openssl pkcs12 -in <p12Path> -nocerts -passin pass:"<p12Pwd>" -passout pass:"<p12Pwd>" | grep 'friendlyName'
    core.debug('getting the P12 private key name');    
    if (!p12Pwd) {
        // if password is null or not defined, set it to empty
        p12Pwd = '';
    }
    // since we can't suppress the private key bytes, encrypt them before we pass them to grep.
    const privateKeyPassword = p12Pwd ? p12Pwd : generatePassword();
    let privateKeyName: string | undefined;
    const opensslPathCmd = await io.which('openssl', true);
    //we pipe through grep so we we don't log the private key to the console.
    //even if it's encrypted, it's noise and could cause concern for some users.
    const grepCmd: string = await io.which('grep', true);

    await exec.exec(opensslPathCmd, ['pkcs12', '-in', p12Path, '-out', '/tmp/p12privkeyname.tmp', '-nocerts', '-passin', 'pass:' + p12Pwd, '-passout', 'pass:' + privateKeyPassword]);

    const grepOpts : execint.ExecOptions = {};
    grepOpts.listeners = {
        stdout: (data: Buffer) => {
            if (data) {
                // find the private key name
                let trimmedData = data.toString().trim();
    
                const match = trimmedData.match(/friendlyName: (.*)/);
                if (match && match[1]) {
                    privateKeyName = match[1].trim();
                }
            }        }
    };
    await exec.exec(grepCmd, ['friendlyName', '/tmp/p12privkeyname.tmp'], grepOpts);
    
    core.debug('P12 private key name = ' + privateKeyName);
    if (!privateKeyName) {
        throw new Error('P12PrivateKeyNameNotFound: ' + p12Path);
    }

    return privateKeyName;
}

/**
 * Set the partition_id ACL so codesign has permission to use the signing key.
 */
async function setKeyPartitionList(keychainPath: string, keychainPwd: string, privateKeyName: string) {
    // security set-key-partition-list -S apple-tool:,apple: -s -l <privateKeyName> -k <keychainPwd> <keychainPath>
    // n.b. This command could update multiple keys (e.g. an expired signing key and a newer signing key.)

    if (privateKeyName) {
        core.debug(`Setting the partition_id ACL for ${privateKeyName}`);

        // "If you'd like to run /usr/bin/codesign with the key, "apple:" must be an element of the partition list." - security(1) man page.
        // When you sign into your developer account in Xcode on a new machine, you get a private key with partition list "apple:". However
        // "security import a.p12 -k login.keychain" results in the private key with partition list "apple-tool:". I'm preserving import's
        // "apple-tool:" and adding the "apple:" codesign needs.
        const partitionList = 'apple-tool:,apple:';

        let setKeyCommand = await io.which('security', true); 
        let setKeyArgs = ['set-key-partition-list', '-S', partitionList, '-s', '-l', privateKeyName, '-k', keychainPwd, keychainPath];
        let unknownCommandErrorFound: boolean = false;
        let incorrectPasswordErrorFound: boolean;
        const setKeyOpts : execint.ExecOptions = {};
        // Watch for "unknown command". set-key-partition-list was added in Sierra (macOS v10.12)
        setKeyOpts.listeners = {
            errline: (line: string) => {
                if (!unknownCommandErrorFound && line.includes('security: unknown command')) {
                    unknownCommandErrorFound = true;
                }
            }
        };

        try {
            await exec.exec(setKeyCommand, setKeyArgs, setKeyOpts);
        } catch (err) {
            if (unknownCommandErrorFound) {
                // If we're on an older OS, we don't need to run set-key-partition-list.
                console.log('SetKeyPartitionListCommandNotFound');
            } else {
                core.error(err);
                throw new Error('SetKeyPartitionListCommandFailed');
            }
        }
    }
}

function getUserProvisioningProfilesPath(): string {
    core.debug('getUserProvisioningProfilesPath()');
    return path.resolve(process.env['HOME'] || '/', 'Library', 'MobileDevice', 'Provisioning Profiles');
}

function getProvisioningProfilePath(uuid: string, provProfilePath?: string): string {
    let profileExtension: string = '';
    if (provProfilePath) {
        profileExtension = path.extname(provProfilePath);
    }
    return path.resolve(getUserProvisioningProfilesPath(), uuid.trim().concat(profileExtension));
}

function generatePassword(): string {
    return Math.random().toString(36);
}

function splitIntoKeyValue(line: string): {key: string, value: string} | undefined {
    // Don't use `split`. The value may contain `=` (e.g. "/UID=E848ASUQZY/CN=iPhone Developer: ...")
    const index: number = line.indexOf('=');

    if (index) {
        return {key: line.substring(0, index), value: line.substring(index + 1)};
    } else {
        return undefined;
    }
}

async function getProvisioningProfileDetails(profProfilePath: string) {
    core.debug('getProvisioningProfileDetails()');

    if (ioutils.exists(profProfilePath)) {
        let securityCmd = await io.which('security', true); 
        let provProfileDetails: string | undefined;

        const getCloudOpts : execint.ExecOptions = {};
        getCloudOpts.listeners = {
            stdout: (data: Buffer) => {
                if (data) {
                    if (provProfileDetails) {
                        provProfileDetails = provProfileDetails.concat(data.toString().trim().replace(/[,\n\r\f\v]/gm, ''));
                    } else {
                        provProfileDetails = data.toString().trim().replace(/[,\n\r\f\v]/gm, '');
                    }
                }
            }
        };
        await exec.exec(securityCmd, ['cms', '-D', '-i', profProfilePath], getCloudOpts);
        core.debug('called security cms -D -i ' + profProfilePath);
        
        return provProfileDetails;
    } else {
        core.error('supplied provisioning profile path does not exist.');
        throw new Error('ProvProfileNotFound');
    }
}

async function saveProvisioningProfileDetails(profProfilePath: string, writeToFile: string) {
    core.debug('saveProvisioningProfileDetails()');
    let details = await getProvisioningProfileDetails(profProfilePath);
    
    if (details) {
        //write the provisioning profile to a plist
        ioutils.writeFile(writeToFile, details);
        core.debug('wrote provisioning profile as plist to ' + writeToFile);
    } else {
        throw new Error('ProvProfileDetailsNotFound: ' + profProfilePath);
    }

    return details;
}

async function execPlistBuddyCommand(command: string, plistfile: string) {
    let results: string | undefined;
    let plistCmd = await io.which('/usr/libexec/PlistBuddy', true); 
    let plistArgs = ['-c', command, plistfile];

    const plistOpts : execint.ExecOptions = {};
    plistOpts.listeners = {
        stdout: (data: Buffer) => {
            if (data) {
                results = data.toString().trim();
            }
        }
    }
    await exec.exec(plistCmd, plistArgs, plistOpts);

    return results;
}