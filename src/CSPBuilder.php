<?php

namespace Bepsvpt\CSPBuilder;

class CSPBuilder
{
    /**
     * @var array
     */
    protected $policies = [];

    /**
     * @var bool
     */
    protected $needsCompile = true;

    /**
     * @var string
     */
    protected $compiled = '';

    /**
     * @var bool
     */
    protected $reportOnly = false;

    /**
     * @var bool
     */
    protected $httpsTransform = true;

    /**
     * @var string[]
     */
    protected static $directives = [
        'base-uri',
        'default-src',
        'child-src',
        'connect-src',
        'font-src',
        'form-action',
        'frame-ancestors',
        'frame-src',
        'img-src',
        'media-src',
        'object-src',
        'plugin-types',
        'script-src',
        'style-src',
    ];

    /**
     * Constructor.
     *
     * @param array $policy
     */
    public function __construct(array $policy = [])
    {
        $this->policies = $policy;
    }

    /**
     * Get an associative array of headers to return.
     *
     * @return string[]
     */
    public function getHeaderArray(): array
    {
        if ($this->needsCompile) {
            $this->compile();
        }

        $key = $this->reportOnly
            ? 'Content-Security-Policy-Report-Only'
            : 'Content-Security-Policy';

        return [$key => $this->compiled];
    }

    /**
     * Compile the current policies into a CSP header.
     *
     * @return string
     */
    protected function compile(): string
    {
        $ruleKeys = array_keys($this->policies);

        $this->reportOnly = in_array('report-only', $ruleKeys)
            ? boolval($this->policies['report-only'])
            : false;

        $compiled = [];

        foreach (self::$directives as $directive) {
            if (! in_array($directive, $ruleKeys)) {
                continue;
            } elseif (empty($ruleKeys) && 'base-uri' === $directive) {
                continue;
            }

            $compiled[] = $this->compileSubgroup($directive, $this->policies[$directive]);
        }

        if (! empty($this->policies['report-uri'])) {
            $compiled[] = sprintf('report-uri %s; ', $this->policies['report-uri']);
        }

        if (! empty($this->policies['upgrade-insecure-requests'])) {
            $compiled[] = 'upgrade-insecure-requests';
        }

        $this->needsCompile = false;

        return $this->compiled = implode('', $compiled);
    }

    /**
     * Compile a subgroup into a policy string.
     *
     * @param string $directive
     * @param mixed $policies
     *
     * @return string
     */
    protected function compileSubgroup(string $directive, $policies = null): string
    {
        if ('*' === $policies) {
            // Don't even waste the overhead adding this to the header
            return '';
        } elseif (empty($policies)) {
            if ('plugin-types' === $directive) {
                return '';
            }

            return sprintf("%s 'none'; ", $directive);
        }

        $ret = $directive.' ';

        if ('plugin-types' === $directive) {
            // Expects MIME types, not URLs
            return sprintf('%s%s; ', $ret, implode(' ', $policies['allow']));
        }

        if (! empty($policies['self'])) {
            $ret .= "'self' ";
        }

        if (! empty($policies['allow'])) {
            foreach ($policies['allow'] as $url) {
                $url = filter_var($url, FILTER_SANITIZE_URL);

                if ($url !== false) {
                    if (($this->isHTTPSConnection() && $this->httpsTransform) || ! empty($this->policies['upgrade-insecure-requests'])) {
                        $url = str_replace('http://', 'https://', $url);
                    }

                    $ret .= $url.' ';
                }
            }
        }

        if (! empty($policies['hashes'])) {
            foreach ($policies['hashes'] as $hash) {
                foreach ($hash as $algo => $value) {
                    // https://www.w3.org/TR/CSP/#grammardef-hash-source
                    if (! in_array($algo, ['sha256', 'sha384', 'sha512'])) {
                        continue;
                    } elseif (base64_encode(base64_decode($value, true)) !== $value) {
                        continue;
                    }

                    $ret .= sprintf("'%s-%s' ", $algo, $value);
                }
            }
        }

        if (! empty($policies['nonces'])) {
            foreach ($policies['nonces'] as $nonce) {
                // https://www.w3.org/TR/CSP/#grammardef-nonce-source
                if (base64_encode(base64_decode($nonce, true)) !== $nonce) {
                    continue;
                }

                $ret .= sprintf("'nonce-%s' ", $nonce);
            }
        }

        if (! empty($policies['types'])) {
            foreach ($policies['types'] as $type) {
                $ret .= $type.' ';
            }
        }

        if (! empty($policies['unsafe-inline'])) {
            $ret .= "'unsafe-inline' ";
        }

        if (! empty($policies['unsafe-eval'])) {
            $ret .= "'unsafe-eval' ";
        }

        if (! empty($policies['data'])) {
            $ret .= 'data: ';
        }

        return rtrim($ret, ' ').'; ';
    }

    /**
     * Is this user currently connected over HTTPS?
     *
     * @return bool
     */
    protected function isHTTPSConnection(): bool
    {
        $https = filter_input(INPUT_SERVER, 'HTTPS');

        return ! empty($https) && 'off' !== strtolower($https);
    }

    /**
     * Disable that HTTP sources get converted to HTTPS if the connection is such.
     *
     * @return CSPBuilder|$this|static
     */
    public function disableHttpTransformOnHttpsConnection(): self
    {
        $this->needsCompile = $this->httpsTransform !== false;

        $this->httpsTransform = false;

        return $this;
    }
}
