import { Route, Routes } from "react-router-dom";
import Layout from "./components/Layout";
import Dashboard from "./pages/Dashboard";
import ScanDetail from "./pages/ScanDetail";

export default function App() {
  return (
    <Layout>
      <Routes>
        <Route path="/" element={<Dashboard />} />
        <Route path="/scans/:id" element={<ScanDetail />} />
      </Routes>
    </Layout>
  );
}
