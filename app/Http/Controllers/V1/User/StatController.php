<?php

namespace App\Http\Controllers\V1\User;

use App\Http\Controllers\Controller;
use App\Models\StatUser;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;

class StatController extends Controller
{
    public function getTrafficLog(Request $request)
    {
        $logs = StatUser::select([
            'u',
            'd',
            'record_at',
            'user_id',
            DB::raw('1 as server_rate') // 这里把倍率固定成1
        ])
        ->where('user_id', $request->user['id'])
        ->where('record_at', '>=', strtotime(date('Y-m-1')))
        ->orderBy('record_at', 'DESC')
        ->get();

        return response([
            'data' => $logs
        ]);
    }
}
