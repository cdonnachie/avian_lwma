#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include "lwma.hpp"
#include "big256.hpp"

namespace py = pybind11;

PYBIND11_MODULE(_core, m) {
    m.doc() = "avian_lwma core (LWMA v3, per-algo windows)";

    py::class_<HeaderLite>(m, "HeaderLite")
        .def(py::init<>())
        .def_readwrite("time", &HeaderLite::time)
        .def_readwrite("version", &HeaderLite::version)
        .def_readwrite("bits", &HeaderLite::bits);

    m.def("next_bits_window",
        [](const std::vector<HeaderLite>& window,
           uint32_t target_spacing_s,
           uint32_t N,
           const std::string& pow_limit_hex) {
            if (window.empty()) throw std::runtime_error("window empty");
            Big256 limit = Big256::from_hex_be(pow_limit_hex);
            return lwma_next_bits(window, target_spacing_s, N, limit);
        },
        py::arg("window"), py::arg("target_spacing_s"), py::arg("N"), py::arg("pow_limit_hex"),
        "Compute next compact bits using LWMA v3 over a per-algo window (oldest->newest)."
    );
}
