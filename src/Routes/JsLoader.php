<?php

namespace Tualo\Office\EncryptedData\Routes;

use Tualo\Office\Basic\TualoApplication as App;
use Tualo\Office\Basic\Route as BasicRoute;

class JsLoader extends \Tualo\Office\Basic\RouteWrapper
{
    public static function scope(): string
    {
        return 'encrypted-data';
    }

    public static function register()
    {
        BasicRoute::add('/jsencrypteddata/(?P<file>[\w.\/\-]+).js', function ($matches) {
            App::contenttype('application/javascript');
            if (file_exists(dirname(__DIR__, 1) . '/js/lazy/' . $matches['file'] . '.js')) {
                App::etagFile(dirname(__DIR__, 1) . '/js/lazy/' . $matches['file'] . '.js', true);
                BasicRoute::$finished = true;
                http_response_code(200);
            }
        }, ['get'], false);
    }
}
