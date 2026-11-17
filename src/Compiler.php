<?php

namespace Tualo\Office\EncryptedData;

use Tualo\Office\ExtJSCompiler\ICompiler;
use Tualo\Office\ExtJSCompiler\CompilerHelper;

class Compiler implements ICompiler
{
    public static function getFiles()
    {
        return CompilerHelper::getFiles(__DIR__, 'encrypted-data', 10004);
    }
}
