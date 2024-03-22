import axios from 'axios'
import React, { createContext, useEffect, useState, useMemo } from 'react'

// create context instance
export const AuthContext = createContext()

// auth provider component
function AuthProvider(props) {

const [token,setToken] = useState(false)

useEffect(() => {
    if(token) {
        axios.defaults.headers.common["Authorization"] = token
    } else {
        delete axios.defaults.headers.common["Authorization"]
    }
},[token])

const contextToken = useMemo(() => ({
    token
}), [token])
   

  return (
   <AuthContext.Provider value={{contextToken, setToken }} >
     {
     props.children
     }
   </AuthContext.Provider>
  )
}

export default AuthProvider
