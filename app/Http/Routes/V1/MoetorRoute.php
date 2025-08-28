<?php


namespace App\Http\Routes\V1;


use Illuminate\Contracts\Routing\Registrar;

class MoetorRoute
{
    public function map(Registrar $router)
    {
        $router->group([], function ($router) {
            $router->get('/moetor/config', 'V1\\Moetor\\MoetorController@config');
        });
    }
}
