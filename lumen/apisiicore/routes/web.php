<?php

/** @var \Laravel\Lumen\Routing\Router $router */

$router->get('/health', function () {
    return response()->json(['status' => 'ok']);
});

$router->group(['middleware' => 'api.key'], function () use ($router) {
    $router->post('/api/RCV/compras/{month}/{year}',      'Sii\RCV\PurchasesController@montly');
    $router->post('/api/RCV/compras/{day}/{month}/{year}', 'Sii\RCV\PurchasesController@diary');

    $router->post('/api/RCV/ventas/{month}/{year}',       'Sii\RCV\SalesController@montly');
    $router->post('/api/RCV/ventas/{day}/{month}/{year}',  'Sii\RCV\SalesController@diary');
});
