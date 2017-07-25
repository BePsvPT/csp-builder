<?php

namespace Bepsvpt\CSPBuilder;

use \ParagonIE\ConstantTime\Base64;

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
     * @param array $policy
     */
    public function __construct(array $policy = [])
    {
        $this->policies = $policy;
    }
    
    /**
     * Compile the current policies into a CSP header
     * 
     * @return string
     */
    public function compile(): string
    {
        $ruleKeys = \array_keys($this->policies);
        if (\in_array('report-only', $ruleKeys)) {
            $this->reportOnly = !!$this->policies['report-only'];
        } else {
            $this->reportOnly = false;
        }
        
        $compiled = [];
        
        foreach(self::$directives as $dir) {
            if (\in_array($dir, $ruleKeys)) {
                if (empty($ruleKeys)) {
                    if ($dir === 'base-uri') {
                        continue;
                    }
                }
                $compiled []= $this->compileSubgroup(
                    $dir,
                    $this->policies[$dir]
                );
            }
        }
        
        if (!empty($this->policies['report-uri'])) {
            $compiled []= 'report-uri ' . $this->policies['report-uri'] . '; ';
        }
        if (!empty($this->policies['upgrade-insecure-requests'])) {
            $compiled []= 'upgrade-insecure-requests';
        }
        
        $this->compiled = \implode('', $compiled);
        $this->needsCompile = false;
        return $this->compiled;
    }
    
    /**
     * Add a source to our allow white-list
     * 
     * @param string $directive
     * @param string $path
     * 
     * @return CSPBuilder
     */
    public function addSource(string $directive, string $path): self
    {
        switch ($directive) {
            case 'child':
            case 'frame':
            case 'frame-src':
                $directive = 'child-src';
                break;
            case 'connect':
            case 'socket':
            case 'websocket':
                $directive = 'connect-src';
                break;
            case 'font':
            case 'fonts':
                $directive = 'font-src';
                break;
            case 'form':
            case 'forms':
                $directive = 'form-action';
                break;
            case 'ancestor':
            case 'parent':
                $directive = 'frame-ancestors';
                break;
            case 'img':
            case 'image':
            case 'image-src':
                $directive = 'img-src';
                break;
            case 'media':
                $directive = 'media-src';
                break;
            case 'object':
                $directive = 'object-src';
                break;
            case 'js':
            case 'javascript':
            case 'script':
            case 'scripts':
                $directive = 'script-src';
                break;
            case 'style':
            case 'css':
            case 'css-src':
                $directive = 'style-src';
                break;
        }
        $this->policies[$directive]['allow'][] = $path;
        return $this;
    }
    
    /**
     * Add a directive if it doesn't already exist
     * 
     * If it already exists, do nothing
     * 
     * @param string $key
     * @param mixed $value
     * 
     * @return CSPBuilder
     */
    public function addDirective(string $key, $value = null): self
    {
        if ($value === null) {
            if (!isset($this->policies[$key])) {
                $this->policies[$key] = true;
            }
        } elseif (empty($this->policies[$key])) {
            $this->policies[$key] = $value;
        }
        return $this;
    }
    
    /**
     * Add a plugin type to be added
     * 
     * @param string $mime
     * @return CSPBuilder
     */
    public function allowPluginType(string $mime = 'text/plain'): self
    {
        $this->policies['plugin-types']['types'] []= $mime;
        
        $this->needsCompile = true;
        return $this;
    }

    /**
     * Get the formatted CSP header 
     * 
     * @return string
     */
    public function getCompiledHeader(): string
    {
        if ($this->needsCompile) {
            $this->compile();
        }

        return $this->compiled;
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
        $return = [];
        foreach ($this->getHeaderKeys() as $key) {
            $return[$key] = $this->compiled;
        }
        return $return;
    }
    
    /**
     * Add a new hash to the existing CSP
     * 
     * @param string $directive
     * @param string $script
     * @param string $algorithm
     * @return CSPBuilder
     */
    public function hash(
        string $directive = 'script-src',
        string $script = '',
        string $algorithm = 'sha384'
    ): self {
        $ruleKeys = \array_keys($this->policies);
        if (\in_array($directive, $ruleKeys)) {
            $this->policies[$directive]['hashes'] []= [
                $algorithm => Base64::encode(
                    \hash($algorithm, $script, true)
                )
            ];
        }
        return $this;
    }
    
    /**
     * Add a new (pre-calculated) base64-encoded hash to the existing CSP
     * 
     * @param string $directive
     * @param string $hash
     * @param string $algorithm
     * @return CSPBuilder
     */
    public function preHash(
        string $directive = 'script-src',
        string $hash = '',
        string $algorithm = 'sha384'
    ): self {
        $ruleKeys = \array_keys($this->policies);
        if (\in_array($directive, $ruleKeys)) {
            $this->policies[$directive]['hashes'] []= [
                $algorithm => $hash
            ];
        }
        return $this;
    }

    /**
     * Add a new nonce to the existing CSP
     *
     * @param string $directive
     * @param string $nonce (if empty, it will be generated)
     * @return null|string
     */
    public function nonce(string $directive = 'script-src', string $nonce = ''): string
    {
        $ruleKeys = \array_keys($this->policies);
        if (!\in_array($directive, $ruleKeys)) {
            return '';
        }

        if (empty($nonce)) {
            $nonce = Base64::encode(\random_bytes(18));
        }
        $this->policies[$directive]['nonces'] []= $nonce;
        return $nonce;
    }

    /**
     * Send the compiled CSP as a header()
     * 
     * @return boolean
     * @throws \Exception
     */
    public function sendCSPHeader(): bool
    {
        if (\headers_sent()) {
            throw new \Exception('Headers already sent!');
        }

        if ($this->needsCompile) {
            $this->compile();
        }

        foreach ($this->getHeaderKeys() as $key) {
            \header($key.': '.$this->compiled);
        }

        return true;
    }
    
    /**
     * Set a directive
     * 
     * @param string $key
     * @param mixed $value
     * 
     * @return CSPBuilder
     */
    public function setDirective(string $key, $value = null): self
    {
        $this->policies[$key] = $value;

        return $this;
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
        if ($policies === '*') {
            // Don't even waste the overhead adding this to the header
            return '';
        } elseif (empty($policies)) {
            if ($directive === 'plugin-types') {
                return '';
            }
            return $directive." 'none'; ";
        }
        $ret = $directive.' ';
        if ($directive === 'plugin-types') {
            // Expects MIME types, not URLs
            return $ret . \implode(' ', $policies['allow']).'; ';
        }
        if (!empty($policies['self'])) {
            $ret .= "'self' ";
        }
        
        if (!empty($policies['allow'])) {
            foreach ($policies['allow'] as $url) {
                $url = \filter_var($url, FILTER_SANITIZE_URL);
                if ($url !== false) {
                    if (($this->isHTTPSConnection() && $this->httpsTransformOnHttpsConnections) || !empty($this->policies['upgrade-insecure-requests'])) {
                        $ret .= \str_replace('http://', 'https://', $url).' ';
                    } else {
                        $ret .= $url.' ';
                    }
                }
            }
        }
        
        if (!empty($policies['hashes'])) {
            foreach ($policies['hashes'] as $hash) {
                foreach ($hash as $algo => $hashval) {
                    $ret .= \implode('', [
                        "'",
                        \preg_replace('/[^A-Za-z0-9]/', '', $algo),
                        '-',
                        \preg_replace('/[^A-Za-z0-9\+\/=]/', '', $hashval),
                        "' "
                    ]);
                }
            }
        }
        
        if (!empty($policies['nonces'])) {
            foreach ($policies['nonces'] as $nonce) {
                $ret .= \implode('', [
                    "'nonce-",
                    \preg_replace('/[^A-Za-z0-9\+\/=]/', '', $nonce),
                    "' "
                ]);
            }
        }
        
        if (!empty($policies['types'])) {
            foreach ($policies['types'] as $type) {
                $ret .= $type.' ';
            }
        }
        
        if (!empty($policies['unsafe-inline'])) {
            $ret .= "'unsafe-inline' ";
        }
        if (!empty($policies['unsafe-eval'])) {
            $ret .= "'unsafe-eval' ";
        }
        if (!empty($policies['data'])) {
            $ret .= "data: ";
        }
        return \rtrim($ret, ' ').'; ';
    }
    
    /**
     * Get an array of header keys to return
     * 
     * @return array
     */
    protected function getHeaderKeys(): array
    {
        return [
            $this->reportOnly 
                ? 'Content-Security-Policy-Report-Only'
                : 'Content-Security-Policy'
        ];
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

    /**
     * Enable that HTTP sources get converted to HTTPS if the connection is such.
     *
     * This is enabled by default
     *
     * @return CSPBuilder|$this|static
     */
    public function enableHttpsTransformOnHttpsConnections(): self
    {
        $this->needsCompile = $this->httpsTransformOnHttpsConnections !== true;
        $this->httpsTransformOnHttpsConnections = true;

        return $this;
    }
}
