<?php
namespace ZBateson\GpgPear;

use PHPUnit\Framework\TestCase;
use Crypt_GPG;

/**
 * Description of GpgPearTest
 *
 * @group GpgPear
 * @author Zaahid Bateson
 */
class GpgPearTest extends TestCase
{
    private $pear;

    protected function setUp()
    {
        $this->pear = new Crypt_GPG([
            'homedir' => dirname(__DIR__) . '/_data/keyring',
        ]);
        $this->pear->importKeyFile(dirname(__DIR__) . '/_data/private.gpg');
        $this->pear->importKeyFile(dirname(__DIR__) . '/_data/public.gpg');
    }

    public function testEncryptDecrypt()
    {
        $data = 'Queremos probar este funcion';
        $gpgPear = new GpgPear($this->pear);
        $this->pear->addEncryptKey('zbateson@users.github.com');
        $stream = $gpgPear->encrypt($data);
        $this->assertNotFalse($stream);
        $dec = $gpgPear->decrypt($stream);
        $this->assertNotFalse($dec);
        $this->assertEquals($data, $dec->getContents());
    }

    public function testEncryptDecryptLargeFile()
    {
        $data = 'Queremos probar este funcion';
        while (strlen($data) < 10241) {
            $data .= $data;
        }
        $gpgPear = new GpgPear($this->pear);
        $this->pear->addEncryptKey('zbateson@users.github.com');
        $stream = $gpgPear->encrypt($data);
        $this->assertNotFalse($stream);
        $dec = $gpgPear->decrypt($stream);
        $this->assertNotFalse($dec);
        $this->assertEquals($data, $dec->getContents());
    }

    public function testDecryptFail()
    {
        $gpgPear = new GpgPear($this->pear);
        $this->assertFalse($gpgPear->decrypt('blah-blah-blah'));
    }

    public function testSignVerify()
    {
        $data = 'Queremos probar este funcion';
        $gpgPear = new GpgPear($this->pear);
        $this->pear->addSignKey('zbateson@users.github.com');
        $signature = $gpgPear->sign($data);
        $this->assertTrue($gpgPear->verify($data, $signature));
    }

    public function testSignVerifyLargeFile()
    {
        $data = 'Queremos probar este funcion';
        while (strlen($data) < 10241) {
            $data .= $data;
        }
        $gpgPear = new GpgPear($this->pear);
        $this->pear->addSignKey('zbateson@users.github.com');
        $signature = $gpgPear->sign($data);
        $this->assertTrue($gpgPear->verify($data, $signature));
    }

    public function testVerifyInvalid()
    {
        $gpgPear = new GpgPear($this->pear);
        $this->assertFalse($gpgPear->verify('Test', 'blah-blah-blah'));
    }
}
