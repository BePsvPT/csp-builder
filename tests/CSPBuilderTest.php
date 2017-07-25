<?php

use Bepsvpt\CSPBuilder\CSPBuilder;
use PHPUnit\Framework\TestCase;

class BasicTest extends TestCase
{
    public function test_csp()
    {
        $data = json_decode(file_get_contents(__DIR__.'/vectors/basic-csp.json'), true);

        $csp = new CSPBuilder($data);

        $this->assertEquals(
            trim(file_get_contents(__DIR__.'/vectors/basic-csp.out')),
            $csp->getHeaderArray()['Content-Security-Policy']
        );
    }

    public function test_upgrade_insecure_beats_disable_https_conversion_flag()
    {
        $data = json_decode(file_get_contents(__DIR__.'/vectors/basic-csp.json'), true);

        $data['form-action']['allow'][0] = 'http://example.com';

        $csp = new CSPBuilder($data);

        $csp->disableHttpTransformOnHttpsConnection();

        $header = $csp->getHeaderArray()['Content-Security-Policy'];

        $this->assertContains('https://example.com', $header);
        $this->assertNotContains('http://example.com', $header);
    }
}
