import React, {useContext, useRef} from 'react'
import ContactContext from '../../context/contact/contactContext'
const ContactFilter = () => {
    const contactContext = useContext(ContactContext)
    const text = useRef('')
    const {filterContacts, clearFilter} = contactContext

    const onChange = (e) => {
        if (text.current.value !== '')
        {
            filterContacts(text.current.value)
        }
        else 
        {
            clearFilter()
        }
    }
    // Add useEffect
    
    return (
        <form>
            <input 
            ref={text} 
            type='text' 
            placeholder='Filter Contacts..'
            onChange={onChange}/>
        </form>
    )
}

export default ContactFilter
