import React, { Component } from 'react';
import {NavLink, Route} from 'react-router-dom';

import Login from './Login.js';

import './App.scss';

class App extends Component {
  render() {
    return (
      <div className="App">
        <header>
          <div className="nav">
          <NavLink to="/">Home</NavLink>
          <NavLink to="/sign-up">Sign Up</NavLink>
          <NavLink to="/login">Login</NavLink>
          <NavLink to="/logout">Logout</NavLink>
          </div>
        </header>

        <main>
        {/* <Route path="/sign-up" component={SignUp} /> */}
        <Route path="/login" component={Login} />
        </main>
      </div>
    );
  }
}

export default App;
