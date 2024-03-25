import axios from 'axios'
import React, { createContext, useEffect, useState, useMemo } from 'react'

// create context instance
export const AuthContext = createContext()

// auth provider component
function AuthProvider(props) {
//token
const [token,setToken] = useState(false)
//login status => if login = true, if logout = false
const [login,setLogin] = useState(false)
// login user info
const [currentUser,setCurrentUser] = useState(false)

useEffect(() => {
    if(token) {
        axios.defaults.headers.common["Authorization"] = token
    } else {
        delete axios.defaults.headers.common["Authorization"]
    }
},[token])

const contextToken = useMemo(() => ({
    token,
    login,
    currentUser
}), [token,login,currentUser])
   

  return (
   <AuthContext.Provider value={{contextToken, setToken, setLogin,setCurrentUser }} >
     {
     props.children
     }
   </AuthContext.Provider>
  )
}

export default AuthProvider
