<?php

declare(strict_types=1);

// UserUploadHosts serve files that any account can upload. A program
// downloaded from one carries the host's name but not its vouching: a
// "VMware" installer under github.com/<anyone>/releases is whoever uploaded it.
// Matched against the URL's host and its parent domains.

return [
    'github.com' => true,
    'githubusercontent.com' => true,
    'gitlab.com' => true,
    'bitbucket.org' => true,
    'sourceforge.net' => true,
    'drive.google.com' => true,
    'docs.google.com' => true,
    'sites.google.com' => true,
    'drive.usercontent.google.com' => true,
    'storage.googleapis.com' => true,
    'firebasestorage.googleapis.com' => true,
    'dropbox.com' => true,
    'dropboxusercontent.com' => true,
    'onedrive.live.com' => true,
    '1drv.ms' => true,
    'sharepoint.com' => true,
    'box.com' => true,
    'mediafire.com' => true,
    'mega.nz' => true,
    'wetransfer.com' => true,
    'we.tl' => true,
    'cdn.discordapp.com' => true,
    'media.discordapp.net' => true,
    'amazonaws.com' => true,
    'cloudfront.net' => true,
    'blob.core.windows.net' => true,
    'r2.dev' => true,
    'backblazeb2.com' => true,
    'filesusr.com' => true,
    'storageapi.fleek.co' => true,
    'wasabisys.com' => true,
    'aliyuncs.com' => true,
    'myqcloud.com' => true,
    'filebase.com' => true,
    'digitaloceanspaces.com' => true,
    'linodeobjects.com' => true,
    'archive.org' => true,
    'pixeldrain.com' => true,
    'gofile.io' => true,
    'catbox.moe' => true,
];
