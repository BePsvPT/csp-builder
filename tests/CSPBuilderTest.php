<?php

use Bepsvpt\CSPBuilder\CSPBuilder;
use PHPUnit\Framework\TestCase;

class CSPBuilderTest extends TestCase
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

    public function test_invalid_hash_and_nonce()
    {
        $data = [
            'script-src' => [
                'hashes' => [
                    ['sha128' => 'Y3NwLWJ1aWxkZXI='],
                    ['sha256' => 'Y3NwLWJ-1aWxkZXI='],
                ],

                'nonces' => [
                    'Y3NwLWJ-1aWxkZXI=',
                    'Y3NwLWJ1aWxkZXI=',
                ],
            ],
        ];

        $csp = new CSPBuilder($data);

        $header = $csp->getHeaderArray()['Content-Security-Policy'];

        $this->assertNotContains('sha128-Y3NwLWJ1aWxkZXI=', $header);
        $this->assertNotContains('sha256-Y3NwLWJ-1aWxkZXI=', $header);
        $this->assertNotContains('nonce-Y3NwLWJ-1aWxkZXI=', $header);
        $this->assertContains('nonce-Y3NwLWJ1aWxkZXI=', $header);
    }

    public function test_unsafe_eval_and_inline()
    {
        $data = [
            'script-src' => [
                'unsafe-eval' => true,

                'unsafe-inline' => true,
            ],
        ];

        $csp = new CSPBuilder($data);

        $header = $csp->getHeaderArray()['Content-Security-Policy'];

        $this->assertContains("'unsafe-eval'", $header);
        $this->assertContains("'unsafe-inline'", $header);
    }

    public function test_report_only()
    {
        $data = [
            'report-only' => true,

            'upgrade-insecure-requests' => true,
        ];

        $csp = new CSPBuilder($data);

        $this->assertArrayHasKey('Content-Security-Policy-Report-Only', $csp->getHeaderArray());
        $this->assertArrayNotHasKey('Content-Security-Policy', $csp->getHeaderArray());
    }
}
