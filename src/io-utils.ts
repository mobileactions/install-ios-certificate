import fs = require('fs');

export function exists(path: string): boolean {
    var exist = false;
    try {
        exist = !!(path && fs.statSync(path) != null);
    } catch (err) {
        if (err && err.code === 'ENOENT') {
            exist = false;
        } else {
            throw err;
        }
    }
    return exist;
}

export interface FsOptions {
    encoding?: string;
    mode?: number;
    flag?: string;
}

export function writeFile(file: string, data: string | Buffer, options?: string | FsOptions) {
    if(typeof(options) === 'string'){
        fs.writeFileSync(file, data, {encoding: options});
    }
    else {
        fs.writeFileSync(file, data, options);
    }
}

export interface FsStats extends fs.Stats {

}

/**
 * Get's stat on a path. 
 * Useful for checking whether a file or directory.  Also getting created, modified and accessed time.
 * see [fs.stat](https://nodejs.org/api/fs.html#fs_class_fs_stats)
 * 
 * @param     path      path to check
 * @returns   fsStat 
 */
export function stats(path: string): FsStats {
    return fs.statSync(path);
}