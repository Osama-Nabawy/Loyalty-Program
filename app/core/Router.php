<?php
declare(strict_types=1);

class Router
{
    private array $routes = [];

    public function add(string $path, Closure $handler)
    {
        $this->routes[$path] = $handler;
    }

    public function dispatch(string $path)
    {
        if (array_key_exists($path, $this->routes)) {
            call_user_func($this->routes[$path]);
        } else {
            http_response_code(404);
            echo "404 - Page Not Found";
        }
    }
}
