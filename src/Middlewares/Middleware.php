<?php

namespace Tualo\Office\EncryptedData\Middlewares;

use Tualo\Office\Basic\TualoApplication as App;
use Tualo\Office\Basic\IMiddleware;

class Middleware implements IMiddleware
{
    public static function register()
    {
        App::use('encrypted-data', function () {
            try {
                // Lazy-Klassen werden über Tualo.EncryptedData (Ext.Loader) nachgeladen,
                // siehe src/js/classic/Loader.js und Routes/JsLoader.php
            } catch (\Exception $e) {
                App::set('maintanceMode', 'on');
                App::addError($e->getMessage());
            }
        }, -100);
    }
}
