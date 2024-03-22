import React, { useState } from 'react'
import { toast } from 'react-toastify'
import axios from 'axios'
import { useNavigate, NavLink} from 'react-router-dom'
import { useAuth } from '../Hooks/AuthHook'

function Login() {
  const [user,setUser] = useState({
    
    email: "",
    password: ""
  })

  const navigate = useNavigate()

  // creating instance of context -> (consumer)
  const { setToken } = useAuth()

  const readvalue = (e) => {
    const { name, value } = e.target
    setUser({...user, [name]: value })
  } 

  const submitHandler = async (e) => {
    e.preventDefault()
    try {
      console.log(`new user =`, user)

      await axios.post(`/api/auth/login`, user)
      
     .then(res => {
          toast.success(res.data.msg)
          setToken(res.data.token)
          navigate(`/`)
        }).catch(err => toast.error(err.response.data.msg))
    } catch (err) {
      toast.error(err.message)
    }
  }

  return (
    <div className='container d-flex align-items-center justify-content-center' style={{ height: '100vh'}}>
      <div className="row">
        
        <div className="col-md-6 col-lg-6 col-sm-12">
         <div className="card">
          <div className="card-header text-center bg-white">
            <h4 className="display-4 text-theme">SignIn</h4>
          </div>
          <div className="card-body">
            <form autoComplete="off" onSubmit={submitHandler}>
           
            <div className="form-group mt-2">
              <label htmlFor="email">Email</label>
              <input type="email" name="email" value={user.email} onChange={readvalue} id="email" className='form-control' required />
            </div>
            <div className="form-group mt-2">
              <label htmlFor="password">Password</label>
              <input type="password" name="password" value={user.password} onChange={readvalue} id="password" className='form-control' required />
            </div>
            <div className="form-group mt-2">
              <input type="submit" value="SignIn"  className='btn bg-theme text-white' />
            </div>
            </form>
            <NavLink to={`/register`} className="text-theme float-end">
              New User? Register Here..
            </NavLink>
          </div>
         </div>
        </div>

        <div className="col-md-6 col-lg-6 col-sm-12 d-none d-sm-none d-md-block d-lg-block">
            <img src={`${process.env.PUBLIC_URL}/signin.svg`} alt="" className='ig-fluid' />
        </div>
      </div>
    </div>
  )
}

export default Login
