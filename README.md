# gpg-pear
Implementation of [zbateson/gpg-interface](https://github.com/zbateson/gpg-interface) using [pear/Crypt_GPG](https://github.com/pear/Crypt_GPG).  This library is intended for use with [zbateson/mail-mime-parser](https://github.com/zbateson/mail-mime-parser) to integrate encryption, decryption, signing, or verification with the mail-mime-parser library.

The library isn't intended to abstract pear/Crypt_GPG, and so its expected that any required setup is performed using pear/Crypt_GPG's APIs directly.  [Click here for pear/Crypt_GPG's documentation](https://pear.php.net/manual/en/package.encryption.crypt-gpg.php).

*NOTE*: this library is still a work-in-progress, and its usage in zbateson/mail-mime-parser hasn't yet been completed.

To include it for use in your project, please install via composer:

```
composer require zbateson/gpg-pear
```

## Requirements

gpg-interface requires PHP 5.4 or newer.

## Usage

```
// see Pear's documentation for setup instructions
$pear = new Crypt_GPG([ 'homedir' => '/path/to/dir' ]);

// ...
// specify keys to use, etc...
// ...

$gpgPear = new GpgPear($pear);

// pass it to ZBateson\MailMimeParser

// ... stay tuned
```

## License

BSD licensed - please see [license agreement](https://github.com/zbateson/gpg-interface/blob/master/LICENSE).