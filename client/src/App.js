import React from 'react'
import { BrowserRouter, Routes, Route} from 'react-router-dom'
import Menu from './Component/Menu'
import {ToastContainer} from 'react-toastify'
import Home from './Pages/Home'
import Login from './Pages/Login'
import Register from './Pages/Register'
import Pnf from './Pages/Pnf'
import About from './Pages/About'
import Contact from './Pages/Contact'
import PrivateRoute from './PrivateRouter/PrivateRoute'
import Dashboard from './Pages/Dashboard/Dashboard'

function App() {
  return (
    <BrowserRouter>
        <Menu/>
        <ToastContainer autoClose={4000} position={'top-right'}/>
        <Routes>
          <Route element={<PrivateRoute/>}>
             <Route path={`/dashboard`} element={<Dashboard/>} />
            </Route>
            <Route path={`/`} element={<Home/>} />
            <Route path={`/about`} element={<About/>} />
            <Route path={`/contact`} element={<Contact/>} />
            <Route path={`/login`} element={<Login/>} />
            <Route path={`/register`} element={<Register/>} />
            <Route path={`/*`} element={<Pnf/>} />
        </Routes>
    </BrowserRouter>
  )
}

export default App
