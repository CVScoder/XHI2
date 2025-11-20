#pragma once
#include <crow.h>
#include "../core/event_bus.h"
#include <nlohmann/json.hpp>

void registerEventWS(crow::SimpleApp& app) {
    // -------------------------------------------------
    //  WS endpoint that ESP32 and the Next.js front-end
    //  will both connect to:  /api/ws
    // -------------------------------------------------
    CROW_WEBSOCKET_ROUTE(app, "/api/ws")
        .onopen([](crow::websocket::connection& conn) {
            std::cout << "[WS] client connected to /api/ws" << std::endl;
            EventBus::addClient(&conn);
        })
        .onclose([](crow::websocket::connection& conn,
                    const std::string& reason,
                    uint16_t code) {
            std::cout << "[WS] client disconnected (code=" << code
                      << " reason=" << reason << ")" << std::endl;
            EventBus::removeClient(&conn);
        })
        .onmessage([](crow::websocket::connection& conn,
                      const std::string& data,
                      bool is_binary) {
            // ESP32 sends JSON → forward to every other client
            if (is_binary) {
                // we don’t expect binary frames from ESP32
                return;
            }
            try {
                nlohmann::json msg = nlohmann::json::parse(data);
                EventBus::broadcast(msg);   // <-- goes to all WS clients
            } catch (const std::exception& e) {
                std::cerr << "[WS] bad JSON: " << e.what() << std::endl;
            }
        });

    // -------------------------------------------------
    //  Keep the old /ws endpoint if you still need it
    // -------------------------------------------------
    CROW_WEBSOCKET_ROUTE(app, "/ws")
        .onopen([](crow::websocket::connection& conn) {
            std::cout << "[WS] client connected to /ws" << std::endl;
            EventBus::addClient(&conn);
        })
        .onclose([](crow::websocket::connection& conn,
                    const std::string& reason,
                    uint16_t code) {
            EventBus::removeClient(&conn);
        })
        .onmessage([](crow::websocket::connection& /*conn*/,
                      const std::string& data,
                      bool is_binary) {
            if (!is_binary) {
                try {
                    nlohmann::json msg = nlohmann::json::parse(data);
                    EventBus::broadcast(msg);
                } catch (...) {}
            }
        });
}