<?php

namespace App\Http\Controllers\V1\Moetor;

use App\Http\Controllers\Controller;
use Illuminate\Support\Facades\Http;

class MoetorController extends Controller
{
    public function config()
    {
        $res['data'] = config('moetor');
        return response()->json($res);
        // return response()->json(['status' => 'success']);
    }

}
