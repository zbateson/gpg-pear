<?php
/**
 * This file is part of the zbateson\gpg-interface project.
 *
 * @license http://opensource.org/licenses/bsd-license.php BSD
 */
namespace ZBateson\GpgPear;

use Crypt_GPG;
use Exception;
use GuzzleHttp\Psr7;
use Psr\Http\Message\StreamInterface;
use ZBateson\GpgInterface\AbstractGpg;

/**
 * Implementation of GpgInterface using pear's Crypt_GPG
 *
 * @author Zaahid Bateson
 */
class GpgPear extends AbstractGpg
{
    /**
     * @var Crypt_GPG
     */
    protected $cryptGpg;

    /**
     * Default constructor takes an optional Crypt_GPG object.  If not passed, a
     * new instance of Crypt_GPG is created.
     */
    public function __construct(Crypt_GPG $crypt = null)
    {
        if ($crypt === null) {
            $crypt = new Crypt_GPG();
        }
        $this->cryptGpg = $crypt;
    }

    /**
     * Returns a StreamInterface of the encrypted data contained in the passed
     * stream, or false on failure.
     *
     * @return StreamInterface|boolean
     */
    protected function encryptStream(StreamInterface $in)
    {
        try {
            if ($in->getSize() !== null && $in->getSize() < 10240) {
                return Psr7\stream_for($this->cryptGpg->encrypt($in->getContents()));
            }
            $plain = tempnam(sys_get_temp_dir(), 'plain');
            $enc = tempnam(sys_get_temp_dir(), 'enc');
            $sp = Psr7\stream_for(fopen($plain, 'r+'));
            Psr7\copy_to_stream($in, $sp);
            $sp->close();
            $this->cryptGpg->encryptFile($plain, $enc);
            return Psr7\stream_for(fopen($enc, 'r'));
        } catch (Exception $e) {
            return false;
        }
    }

    /**
     * Returns a StreamInterface of the decrypted data contained in the passed
     * stream, or false on failure.
     *
     * @return StreamInterface|boolean
     */
    protected function decryptStream(StreamInterface $in)
    {
        try {
            if ($in->getSize() !== null && $in->getSize() < 10240) {
                return Psr7\stream_for($this->cryptGpg->decrypt($in->getContents()));
            }
            $enc = tempnam(sys_get_temp_dir(), 'enc');
            $plain = tempnam(sys_get_temp_dir(), 'plain');
            $se = Psr7\stream_for(fopen($enc, 'r+'));
            Psr7\copy_to_stream($in, $se);
            $se->close();
            $this->cryptGpg->decryptFile($enc, $plain);
            return Psr7\stream_for(fopen($plain, 'r'));
        } catch (Exception $e) {
            return false;
        }
    }

    /**
     * Returns the signature of the passed stream, or false on failure.
     *
     * @return string|boolean
     */
    protected function signStream(StreamInterface $in)
    {
        try {
            if ($in->getSize() !== null && $in->getSize() < 10240) {
                return $this->cryptGpg->sign(
                    $in->getContents(),
                    Crypt_GPG::SIGN_MODE_DETACHED
                );
            }
            $plain = tempnam(sys_get_temp_dir(), 'plain');
            $sp = Psr7\stream_for(fopen($plain, 'r+'));
            Psr7\copy_to_stream($in, $sp);
            $sp->close();
            return $this->cryptGpg->signFile($plain, null, Crypt_GPG::SIGN_MODE_DETACHED);
        } catch (Exception $e) {
            return false;
        }
    }

    /**
     * Returns either true if the passed data has been signed with the passed
     * $signature and has been verified, or false otherwise.
     *
     * @return boolean
     */
    protected function verifyStream(StreamInterface $in, $signature)
    {
        try {
            $ret = null;
            if ($in->getSize() !== null && $in->getSize() < 10240) {
                $ret = $this->cryptGpg->verify($in->getContents(), $signature);
            } else {
                $plain = tempnam(sys_get_temp_dir(), 'plain');
                $sp = Psr7\stream_for(fopen($plain, 'r+'));
                Psr7\copy_to_stream($in, $sp);
                $sp->close();
                $ret = $this->cryptGpg->verifyFile($plain, $signature);
            }
            return !empty(array_filter($ret, function ($e) { return $e->isValid(); } ));
        } catch (Exception $e) {
        }
        return false;
    }
}
