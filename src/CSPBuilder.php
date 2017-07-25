<?php

namespace Bepsvpt\CSPBuilder;

class CSPBuilder
{
    /**
     * @var array
     */
    private $policies = [];

    /**
     * @var bool
     */
    private $needsCompile = true;

    /**
     * @var string
     */
    private $compiled = '';

    /**
     * @var bool
     */
    private $reportOnly = false;

    /**
     * @var bool
     */
    protected $httpsTransformOnHttpsConnections = true;

    /**
     * @var string[]
     */
    private static $directives = [
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
        'style-src'
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
     * Compile the current policies into a CSP header
     * 
     * @return string
     */
    public function compile(): string
    {
        $ruleKeys = array_keys($this->policies);

        $this->reportOnly = in_array('report-only', $ruleKeys)
            ? boolval($this->policies['report-only'])
            : false;

        $compiled = [];
        
        foreach(self::$directives as $directive) {
            if (! in_array($directive, $ruleKeys)) {
                continue;
            } elseif (empty($ruleKeys) && 'base-uri' === $directive) {
                continue;
            }

            $compiled[] = $this->compileSubgroup($directive, $this->policies[$directive]);
        }
        
        if (! empty($this->policies['report-uri'])) {
            $compiled[] = sprintf('report-uri %s;', $this->policies['report-uri']);
        }

        if (! empty($this->policies['upgrade-insecure-requests'])) {
            $compiled[] = 'upgrade-insecure-requests';
        }
        
        $this->needsCompile = false;

        return $this->compiled = implode('', $compiled);
    }

    /**
     * Compile a subgroup into a policy string
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
                    if (($this->isHTTPSConnection() && $this->httpsTransformOnHttpsConnections) || ! empty($this->policies['upgrade-insecure-requests'])) {
                        $ret .= str_replace('http://', 'https://', $url).' ';
                    } else {
                        $ret .= $url.' ';
                    }
                }
            }
        }
        
        if (! empty($policies['hashes'])) {
            foreach ($policies['hashes'] as $hash) {
                foreach ($hash as $algo => $hashval) {
                    $ret .= implode('', [
                        "'",
                        preg_replace('/[^A-Za-z0-9]/', '', $algo),
                        '-',
                        preg_replace('/[^A-Za-z0-9\+\/=]/', '', $hashval),
                        "' "
                    ]);
                }
            }
        }
        
        if (! empty($policies['nonces'])) {
            foreach ($policies['nonces'] as $nonce) {
                $ret .= implode('', [
                    "'nonce-",
                    preg_replace('/[^A-Za-z0-9\+\/=]/', '', $nonce),
                    "' "
                ]);
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
            $ret .= "data: ";
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
        if (! empty($_SERVER['HTTPS'])) {
            return $_SERVER['HTTPS'] !== 'off';
        }

        return false;
    }

    /**
     * Disable that HTTP sources get converted to HTTPS if the connection is such.
     *
     * @return CSPBuilder|$this|static
     */
    public function disableHttpsTransformOnHttpsConnections(): self
    {
        $this->needsCompile = $this->httpsTransformOnHttpsConnections !== false;

        $this->httpsTransformOnHttpsConnections = false;

        return $this;
    }
}
