import React, {Component} from 'react';
import axios from 'axios'
import {connect} from 'react-redux';
import {getUser} from '../redux/reducer';

class Auth extends Component {
    constructor(props){
        super(props);
        this.state = {
            email: '',
            password: ''
        }
    }

    componentDidMount(){
        if(this.props.user.email){
            this.props.history.push('/dashboard')
        }
    }
    handleInput = e => {
        this.setState({
            [e.target.name]: e.target.value
        })
    }

    login = (e) => {
        e.preventDefault();
        axios.post('api/login', {email: this.state.email, password: this.state.password})
            .then(res=>{
                //Place user info somewhere the App can access it (local state, redux state, etc)
                this.props.getUser(res.data)

                //Navigate user to the dashboard or other authenticated views
                this.props.history.push('/dashboard')
            }).catch(err=> console.log(err))

    }

    register = (e) => {
        e.preventDefault();
        axios.post('api/register', {email: this.state.email, password: this.state.password})
            .then(res=>{
                //place the user info somewhere the app can access it
                this.props.getUser(res.data)

                //navigate user to dashboard
                this.props.history.push('/dashboard')
            }).catch(err=> console.log(err))

    }

    render(){
        const {email, password} = this.state;

        return (
            <main className='auth-flex'>
                <form className='auth-form'>
                    <input name='email' placeholder='Email' value={email} onChange={e => this.handleInput(e)}/>
                    <input type='password' name='password' placeholder='Password' value={password} onChange={e => this.handleInput(e)}/>
                    <button onClick={e => this.login(e)}>Log In</button>
                    <button onClick={e => this.register(e)}>Register</button>
                </form>
            </main>
        )
    }
}

const mapStateToProps = reduxState => reduxState

export default connect(mapStateToProps, {getUser})(Auth);